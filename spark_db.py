"""
spark-meeting-app — DB abstraction layer.

  SPARK_DB_DRIVER=hana     → SAP HANA Cloud (hdbcli)   — default, used on BTP
  SPARK_DB_DRIVER=postgres → PostgreSQL                 — for local dev

Environment variables (same for both backends):
  SPARK_DB_HOST, SPARK_DB_PORT, SPARK_DB_USER, SPARK_DB_PASSWORD
  SPARK_DB_NAME  (PostgreSQL only, default: spark_meeting)

For HANA, the server also accepts HANA_HOST / HANA_PORT / HANA_USER / HANA_PASSWORD
as legacy fallback (keeps backward-compat with existing BTP env).
"""
import asyncio
import json
import os
import re
from pathlib import Path

DB_DRIVER = os.getenv("SPARK_DB_DRIVER", "hana").lower()
IS_PG = DB_DRIVER == "postgres"

# ── Connection config ──────────────────────────────────────────────────────────

def _hana_cfg():
    host = os.getenv("SPARK_DB_HOST") or os.getenv("HANA_HOST")
    if host:
        return dict(
            address=host,
            port=int(os.getenv("SPARK_DB_PORT") or os.getenv("HANA_PORT", "443")),
            user=os.getenv("SPARK_DB_USER") or os.getenv("HANA_USER", ""),
            password=os.getenv("SPARK_DB_PASSWORD") or os.getenv("HANA_PASSWORD", ""),
            encrypt=True,
            sslValidateCertificate=False,
        )
    creds_file = Path.home() / ".spark_hana_creds.json"
    if creds_file.exists():
        c = json.loads(creds_file.read_text())
        return dict(address=c["host"], port=int(c["port"]),
                    user=c["user"], password=c["password"],
                    encrypt=True, sslValidateCertificate=False)
    raise RuntimeError("No HANA credentials found (set SPARK_DB_HOST/USER/PASSWORD or ~/.spark_hana_creds.json)")


def _pg_cfg():
    return dict(
        host=os.getenv("SPARK_DB_HOST", "localhost"),
        port=int(os.getenv("SPARK_DB_PORT", "5432")),
        dbname=os.getenv("SPARK_DB_NAME", "spark_meeting"),
        user=os.getenv("SPARK_DB_USER", "postgres"),
        password=os.getenv("SPARK_DB_PASSWORD", ""),
    )


def _new_conn():
    if IS_PG:
        import psycopg2
        return psycopg2.connect(**_pg_cfg())
    else:
        from hdbcli import dbapi
        return dbapi.connect(**_hana_cfg())


# ── SQL adaptation (HANA → PostgreSQL) ────────────────────────────────────────

def _pg_upsert(sql: str) -> str:
    """Convert HANA UPSERT...WITH PRIMARY KEY to PostgreSQL INSERT...ON CONFLICT."""
    m = re.match(
        r'UPSERT\s+(\w+)\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)\s*WITH\s+PRIMARY\s+KEY',
        sql.strip(), re.IGNORECASE
    )
    if not m:
        return sql
    table = m.group(1)
    cols = [c.strip() for c in m.group(2).split(',')]
    vals = m.group(3).strip()
    pk = cols[0]
    update_cols = cols[1:]
    set_clause = ', '.join(f'{c}=EXCLUDED.{c}' for c in update_cols)
    placeholders = re.sub(r'\?', '%s', vals)
    return (
        f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders}) "
        f"ON CONFLICT ({pk}) DO UPDATE SET {set_clause}"
    )


def _adapt_sql(sql: str) -> str:
    """Adapt HANA SQL to PostgreSQL when IS_PG."""
    if not IS_PG:
        return sql
    # UPSERT → INSERT ON CONFLICT
    if re.match(r'\s*UPSERT\b', sql, re.IGNORECASE):
        sql = _pg_upsert(sql)
    # Remaining ? → %s (for plain INSERT/UPDATE/SELECT)
    sql = sql.replace('?', '%s')
    # NVARCHAR → VARCHAR, NCLOB → TEXT (for CREATE TABLE)
    sql = re.sub(r'\bNVARCHAR\b', 'VARCHAR', sql, flags=re.IGNORECASE)
    sql = re.sub(r'\bNCLOB\b', 'TEXT', sql, flags=re.IGNORECASE)
    # CREATE TABLE → CREATE TABLE IF NOT EXISTS (avoids needing _is_dup checks)
    sql = re.sub(r'\bCREATE\s+TABLE\s+(?!IF\b)', 'CREATE TABLE IF NOT EXISTS ', sql, flags=re.IGNORECASE)
    return sql


def _adapt_params(params):
    if not params:
        return ()
    return tuple(params)


# ── Error helpers ──────────────────────────────────────────────────────────────

def _hana_is_dup(e) -> bool:
    """True when the DB error means the object already exists (safe to ignore)."""
    s = str(e)
    sl = s.lower()
    # HANA error codes
    if any(code in s for code in ("261", "288", "308", "386")):
        return True
    if any(p in sl for p in ("duplicate", "already exists", "already defined", "existing table")):
        return True
    # PostgreSQL: DuplicateTable (42P07) or UniqueViolation (23505)
    if IS_PG:
        try:
            pgcode = getattr(e, 'pgcode', None) or getattr(getattr(e, 'diag', None), 'sqlstate', None)
            if pgcode in ('42P07', '23505', '42710'):
                return True
        except Exception:
            pass
    return False


# ── Row helpers ────────────────────────────────────────────────────────────────

def _row_to_dict(description, row):
    cols = [d[0].lower() for d in description]
    result = {}
    for col, val in zip(cols, row):
        if hasattr(val, 'read'):
            val = val.read()
        result[col] = val
    return result


def _from_hana(row: dict) -> dict:
    """Parse a {id, data_json} row into a full dict (works for both HANA and PG)."""
    d = json.loads(row.get("data_json") or "{}")
    d["id"] = row.get("id", d.get("id", ""))
    return d


# ── Core async helpers ─────────────────────────────────────────────────────────

async def _hq(sql: str, params: tuple = ()) -> list[dict]:
    """SELECT → list of dicts."""
    adapted_sql = _adapt_sql(sql)
    adapted_params = _adapt_params(params)

    def _run():
        conn = _new_conn()
        try:
            if IS_PG:
                import psycopg2.extras
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(adapted_sql, adapted_params)
                    return [dict(r) for r in cur.fetchall()]
            else:
                cur = conn.cursor()
                cur.execute(adapted_sql, adapted_params)
                return [_row_to_dict(cur.description, row) for row in cur.fetchall()]
        finally:
            conn.close()

    return await asyncio.to_thread(_run)


async def _hx(sql: str, params: tuple = ()) -> None:
    """INSERT / UPDATE / DELETE / CREATE TABLE."""
    adapted_sql = _adapt_sql(sql)
    adapted_params = _adapt_params(params)

    def _run():
        conn = _new_conn()
        try:
            cur = conn.cursor()
            cur.execute(adapted_sql, adapted_params)
            conn.commit()
        finally:
            conn.close()

    await asyncio.to_thread(_run)


async def _hbatch(sql: str, param_list: list) -> int:
    """Execute the same SQL for many param sets; returns success count."""
    adapted_sql = _adapt_sql(sql)

    def _run():
        conn = _new_conn()
        try:
            cur = conn.cursor()
            n = 0
            for p in param_list:
                try:
                    cur.execute(adapted_sql, _adapt_params(p))
                    n += 1
                except Exception as e:
                    print(f"[hbatch] WARN: {e}", flush=True)
            conn.commit()
            return n
        finally:
            conn.close()

    return await asyncio.to_thread(_run)


async def _hx_txn(ops: list[tuple]) -> None:
    """Run multiple (sql, params) statements atomically."""
    def _run():
        conn = _new_conn()
        try:
            cur = conn.cursor()
            for sql, params in ops:
                cur.execute(_adapt_sql(sql), _adapt_params(params))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    await asyncio.to_thread(_run)


# ── Domain upserts ─────────────────────────────────────────────────────────────

async def _upsert_reg(doc_id: str, reg: dict) -> None:
    email    = str(reg.get("email", "") or "").lower()[:256]
    session  = str(reg.get("session", "") or "")[:1024]
    attended = bool(reg.get("attended", False))
    await _hx(
        "UPSERT SPARK_REGISTRATIONS (id, email, session, attended, data_json) "
        "VALUES (?, ?, ?, ?, ?) WITH PRIMARY KEY",
        (doc_id, email, session, attended, json.dumps(reg))
    )


async def _upsert_user(doc_id: str, user: dict) -> None:
    await _hx(
        "UPSERT SPARK_USERS (id, email, data_json) VALUES (?, ?, ?) WITH PRIMARY KEY",
        (doc_id, str(user.get("email", "") or "").lower(), json.dumps(user))
    )
