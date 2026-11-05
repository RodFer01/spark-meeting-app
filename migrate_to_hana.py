#!/usr/bin/env python3
"""
Migrate Firestore backup → SAP HANA Cloud (spark-meeting-app)

Usage:
    python migrate_to_hana.py [backup_file]

If backup_file is not specified, uses the most recent file in backups/.

Requires HANA credentials in one of:
  - VCAP_SERVICES env var (BTP CF context)
  - ~/.spark_hana_creds.json (local dev)
"""

import json
import os
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from hdbcli import dbapi


def _hana_oauth_token(uaa: dict) -> str:
    import base64
    url = uaa["url"] + "/oauth/token"
    credentials = base64.b64encode(
        f"{uaa['clientid']}:{uaa['clientsecret']}".encode()
    ).decode()
    req = urllib.request.Request(
        url,
        data=b"grant_type=client_credentials",
        headers={
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())["access_token"]


DDL = [
    """CREATE TABLE SPARK_SESSIONS (
        id NVARCHAR(128) PRIMARY KEY,
        title NCLOB,
        area NVARCHAR(128),
        data_json NCLOB,
        updated_at NVARCHAR(64)
    )""",
    """CREATE TABLE SPARK_ESS_TEMPLATES (
        key NVARCHAR(128) PRIMARY KEY,
        container NVARCHAR(256),
        slot NVARCHAR(128)
    )""",
    """CREATE TABLE SPARK_REGISTRATIONS (
        id NVARCHAR(128) PRIMARY KEY,
        email NVARCHAR(256),
        session NVARCHAR(1024),
        attended BOOLEAN DEFAULT FALSE,
        data_json NCLOB
    )""",
    """CREATE TABLE SPARK_EMAIL_JOBS (
        id NVARCHAR(128) PRIMARY KEY,
        status NVARCHAR(32),
        to_email NVARCHAR(256),
        to_name NCLOB,
        subject NCLOB,
        html NCLOB,
        container NVARCHAR(256),
        slot NVARCHAR(128),
        created_at NVARCHAR(64),
        updated_at NVARCHAR(64),
        from_email NVARCHAR(256),
        error NCLOB
    )""",
    """CREATE TABLE SPARK_INTELLIGENCE_SNAPSHOTS (
        id NVARCHAR(128) PRIMARY KEY,
        session NCLOB,
        session_area NVARCHAR(256),
        analyzed_at NVARCHAR(64),
        data_json NCLOB
    )""",
    """CREATE TABLE SPARK_USERS (
        id NVARCHAR(128) PRIMARY KEY,
        email NVARCHAR(256),
        data_json NCLOB
    )""",
    """CREATE TABLE SPARK_ANALYTICS_CAMPAIGNS (
        id NVARCHAR(128) PRIMARY KEY,
        data_json NCLOB,
        uploaded_at NVARCHAR(64)
    )""",
    """CREATE TABLE SPARK_ANALYTICS_REGISTRATIONS (
        id NVARCHAR(128) PRIMARY KEY,
        data_json NCLOB,
        uploaded_at NVARCHAR(64)
    )""",
]


def _get_conn():
    # Explicit creds file takes priority (bypasses OAuth-only service bindings)
    creds_file = Path.home() / ".spark_hana_creds.json"
    if creds_file.exists():
        creds = json.loads(creds_file.read_text())
        return dbapi.connect(
            address=creds["host"],
            port=int(creds["port"]),
            user=creds["user"],
            password=creds["password"],
            encrypt=True,
            sslValidateCertificate=False,
        )
    # Env vars (user-provided, same pattern as dh-api)
    hana_host = os.environ.get("HANA_HOST")
    if hana_host:
        return dbapi.connect(
            address=hana_host,
            port=int(os.environ["HANA_PORT"]),
            user=os.environ["HANA_USER"],
            password=os.environ["HANA_PASSWORD"],
            encrypt=True,
            sslValidateCertificate=False,
        )
    raise RuntimeError(
        "No HANA credentials found. Provide ~/.spark_hana_creds.json or HANA_HOST/USER/PASSWORD/PORT env vars."
    )


# ── Firestore format conversion ───────────────────────────────────────────────

def _from_fs(field: dict):
    if "nullValue"      in field: return None
    if "booleanValue"   in field: return field["booleanValue"]
    if "integerValue"   in field: return int(field["integerValue"])
    if "doubleValue"    in field: return field["doubleValue"]
    if "timestampValue" in field: return field["timestampValue"][:10]
    if "stringValue"    in field: return field["stringValue"]
    if "arrayValue"     in field: return [_from_fs(v) for v in field["arrayValue"].get("values", [])]
    if "mapValue"       in field: return {k: _from_fs(v) for k, v in field["mapValue"].get("fields", {}).items()}
    return None


def _doc_to_dict(doc: dict) -> dict:
    result = {k: _from_fs(v) for k, v in doc.get("fields", {}).items()}
    result["id"] = doc.get("name", "").split("/")[-1]
    return result


# ── Schema creation ───────────────────────────────────────────────────────────

def create_schema(conn) -> None:
    cur = conn.cursor()
    for ddl in DDL:
        # Extract table name: CREATE TABLE <name>
        tokens = ddl.strip().split()
        table_name = tokens[2]
        print(f"  {table_name}...", end=" ", flush=True)
        try:
            cur.execute(ddl)
            conn.commit()
            print("ok")
        except Exception as e:
            err_str = str(e).lower()
            if "already exists" in err_str or "existing table" in err_str or "(288)" in err_str:
                print("exists (ok)")
            else:
                print(f"ERROR: {e}")
                raise
    cur.close()


# ── Data migration ────────────────────────────────────────────────────────────

def migrate_sessions(conn, docs: list) -> int:
    cur = conn.cursor()
    n = 0
    for doc in docs:
        d = _doc_to_dict(doc)
        doc_id = d.get("id", "")
        if not doc_id:
            continue
        title = str(d.get("title", "") or "")
        area  = str(d.get("area", "") or "")[:128]
        try:
            cur.execute(
                "UPSERT SPARK_SESSIONS (id, title, area, data_json, updated_at) "
                "VALUES (?, ?, ?, ?, ?) WITH PRIMARY KEY",
                (doc_id, title, area, json.dumps(d), datetime.now(timezone.utc).isoformat())
            )
            n += 1
        except Exception as e:
            print(f"    WARN sessions/{doc_id}: {e}")
    conn.commit()
    cur.close()
    return n


def migrate_registrations(conn, docs: list) -> int:
    cur = conn.cursor()
    n = 0
    for doc in docs:
        d = _doc_to_dict(doc)
        doc_id = d.get("id", "")
        if not doc_id:
            continue
        email    = str(d.get("email", "") or "").lower()[:256]
        session  = str(d.get("session", "") or "")[:1024]
        attended = bool(d.get("attended", False))
        try:
            cur.execute(
                "UPSERT SPARK_REGISTRATIONS (id, email, session, attended, data_json) "
                "VALUES (?, ?, ?, ?, ?) WITH PRIMARY KEY",
                (doc_id, email, session, attended, json.dumps(d))
            )
            n += 1
        except Exception as e:
            print(f"    WARN registrations/{doc_id}: {e}")
    conn.commit()
    cur.close()
    return n


def migrate_email_jobs(conn, docs: list) -> int:
    cur = conn.cursor()
    n = 0
    for doc in docs:
        d = _doc_to_dict(doc)
        doc_id = d.get("id", "")
        if not doc_id:
            continue
        try:
            cur.execute(
                "UPSERT SPARK_EMAIL_JOBS "
                "(id, status, to_email, to_name, subject, html, container, slot, "
                "created_at, updated_at, from_email, error) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) WITH PRIMARY KEY",
                (
                    doc_id,
                    str(d.get("status", "pending") or "pending")[:32],
                    str(d.get("to", "") or d.get("toEmail", "") or "")[:256],
                    str(d.get("toName", "") or ""),
                    str(d.get("subject", "") or ""),
                    str(d.get("html", "") or ""),
                    str(d.get("container", "") or "")[:256],
                    str(d.get("slot", "") or "")[:128],
                    str(d.get("createdAt", "") or "")[:64],
                    str(d.get("updatedAt", "") or datetime.now(timezone.utc).isoformat())[:64],
                    str(d.get("from", "") or d.get("fromEmail", "") or "")[:256],
                    str(d.get("error", "") or ""),
                )
            )
            n += 1
        except Exception as e:
            print(f"    WARN emailJobs/{doc_id}: {e}")
    conn.commit()
    cur.close()
    return n


def migrate_intelligence_snapshots(conn, docs: list) -> int:
    cur = conn.cursor()
    n = 0
    for doc in docs:
        d = _doc_to_dict(doc)
        doc_id = d.get("id", "")
        if not doc_id:
            continue
        session      = str(d.get("session", "") or "")
        session_area = str(d.get("sessionArea", "") or "")[:256]
        analyzed_at  = str(d.get("analyzedAt", "") or "")[:64]
        try:
            cur.execute(
                "UPSERT SPARK_INTELLIGENCE_SNAPSHOTS (id, session, session_area, analyzed_at, data_json) "
                "VALUES (?, ?, ?, ?, ?) WITH PRIMARY KEY",
                (doc_id, session, session_area, analyzed_at, json.dumps(d))
            )
            n += 1
        except Exception as e:
            print(f"    WARN intelligence_snapshots/{doc_id}: {e}")
    conn.commit()
    cur.close()
    return n


def migrate_users(conn, docs: list) -> int:
    cur = conn.cursor()
    n = 0
    for doc in docs:
        d = _doc_to_dict(doc)
        doc_id = d.get("id", "")
        if not doc_id:
            continue
        email = str(d.get("email", "") or "").lower()[:256]
        try:
            cur.execute(
                "UPSERT SPARK_USERS (id, email, data_json) "
                "VALUES (?, ?, ?) WITH PRIMARY KEY",
                (doc_id, email, json.dumps(d))
            )
            n += 1
        except Exception as e:
            print(f"    WARN users/{doc_id}: {e}")
    conn.commit()
    cur.close()
    return n


def migrate_analytics(conn, table: str, docs: list) -> int:
    cur = conn.cursor()
    n = 0
    ts = datetime.now(timezone.utc).isoformat()
    for doc in docs:
        d = _doc_to_dict(doc)
        doc_id = d.get("id", "")
        if not doc_id:
            continue
        try:
            cur.execute(
                f"UPSERT {table} (id, data_json, uploaded_at) "
                "VALUES (?, ?, ?) WITH PRIMARY KEY",
                (doc_id, json.dumps(d), ts)
            )
            n += 1
        except Exception as e:
            print(f"    WARN {table}/{doc_id}: {e}")
    conn.commit()
    cur.close()
    return n


def migrate_ess_templates(conn, special_doc: dict | None) -> int:
    if not special_doc:
        print("  (no ess-templates-config found, skipping)")
        return 0
    cur = conn.cursor()
    n = 0
    template_keys = [
        "confirmation_pt", "confirmation_es",
        "rejection_pt",    "rejection_es",
        "rsvp_pt",         "rsvp_es",
        "teams_link_pt",   "teams_link_es",
    ]
    fields = special_doc.get("fields", {})
    for key in template_keys:
        field = fields.get(key)
        if not field:
            continue
        if "mapValue" in field:
            map_fields = field["mapValue"].get("fields", {})
            container = map_fields.get("container", {}).get("stringValue", "")
            slot      = map_fields.get("slot",      {}).get("stringValue", "body")
        else:
            container = field.get("stringValue", "")
            slot = "body"
        if not container:
            continue
        try:
            cur.execute(
                "UPSERT SPARK_ESS_TEMPLATES (key, container, slot) "
                "VALUES (?, ?, ?) WITH PRIMARY KEY",
                (key, container, slot)
            )
            n += 1
        except Exception as e:
            print(f"    WARN ess_templates/{key}: {e}")
    conn.commit()
    cur.close()
    return n


# ── Verification ──────────────────────────────────────────────────────────────

def verify(conn) -> None:
    cur = conn.cursor()
    tables = [
        "SPARK_SESSIONS", "SPARK_REGISTRATIONS", "SPARK_EMAIL_JOBS",
        "SPARK_INTELLIGENCE_SNAPSHOTS", "SPARK_USERS", "SPARK_ESS_TEMPLATES",
        "SPARK_ANALYTICS_CAMPAIGNS", "SPARK_ANALYTICS_REGISTRATIONS",
    ]
    print("\nRow counts:")
    for t in tables:
        try:
            cur.execute(f"SELECT COUNT(*) FROM {t}")
            count = cur.fetchone()[0]
        except Exception:
            count = "ERROR"
        print(f"  {t:<42} {count!s:>6}")
    cur.close()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) > 1:
        backup_path = Path(sys.argv[1])
    else:
        backups_dir = Path("backups")
        if not backups_dir.exists():
            print("ERROR: backups/ not found. Run backup_firestore.py first.")
            sys.exit(1)
        files = sorted(backups_dir.glob("firestore_backup_*.json"))
        if not files:
            print("ERROR: No backup files in backups/. Run backup_firestore.py first.")
            sys.exit(1)
        backup_path = files[-1]

    print(f"Backup: {backup_path}")
    backup = json.loads(backup_path.read_text())
    print(f"Created: {backup.get('created_at')}")
    collections  = backup.get("collections", {})
    special_docs = backup.get("special_docs", {})

    print("\nConnecting to HANA...")
    conn = _get_conn()
    print("Connected.\n")

    print("Creating schema (IF NOT EXISTS)...")
    create_schema(conn)

    print("\nMigrating data...")

    n = migrate_sessions(conn, collections.get("sessions", []))
    print(f"  sessions:                  {n}")

    ess_doc = special_docs.get("sessions/ess-templates-config")
    n = migrate_ess_templates(conn, ess_doc)
    print(f"  ess_templates:             {n}")

    n = migrate_registrations(conn, collections.get("registrations", []))
    print(f"  registrations:             {n}")

    n = migrate_email_jobs(conn, collections.get("emailJobs", []))
    print(f"  email_jobs:                {n}")

    n = migrate_intelligence_snapshots(conn, collections.get("intelligence_snapshots", []))
    print(f"  intelligence_snapshots:    {n}")

    n = migrate_users(conn, collections.get("users", []))
    print(f"  users:                     {n}")

    n = migrate_analytics(conn, "SPARK_ANALYTICS_CAMPAIGNS", collections.get("analytics_campaigns", []))
    print(f"  analytics_campaigns:       {n}")

    n = migrate_analytics(conn, "SPARK_ANALYTICS_REGISTRATIONS", collections.get("analytics_registrations", []))
    print(f"  analytics_registrations:   {n}")

    verify(conn)
    conn.close()
    print("\nMigration complete.")


if __name__ == "__main__":
    print("Spark Meeting — Firestore → HANA Migration")
    print(f"Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(1)
    except Exception as e:
        print(f"\nFATAL: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)
