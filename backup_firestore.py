#!/usr/bin/env python3
"""
Backup all Firestore collections to a versioned JSON file.

Usage:
    python backup_firestore.py

Output:
    backups/firestore_backup_YYYYMMDD_HHMMSS.json
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

FB_PROJECT = "spark-meeting-63e1b"
FB_API_KEY = os.environ.get("FIREBASE_API_KEY", "AIzaSyDu-8DaHrkbosQDMLRQZKvSyFNVavfl22s")
FS_BASE = f"https://firestore.googleapis.com/v1/projects/{FB_PROJECT}/databases/(default)/documents"

COLLECTIONS = [
    "sessions",
    "registrations",
    "emailJobs",
    "intelligence_snapshots",
    "users",
    "analytics_campaigns",
    "analytics_registrations",
]


def _list_collection(collection: str) -> list[dict]:
    """Fetch all documents from a Firestore collection (handles pagination)."""
    docs = []
    page_token = None
    while True:
        params = {"key": FB_API_KEY, "pageSize": 300}
        if page_token:
            params["pageToken"] = page_token
        r = requests.get(f"{FS_BASE}/{collection}", params=params, timeout=30)
        if r.status_code == 404:
            return docs
        r.raise_for_status()
        body = r.json()
        for doc in body.get("documents", []):
            docs.append(doc)
        page_token = body.get("nextPageToken")
        if not page_token:
            break
    return docs


def _get_doc(path: str) -> dict | None:
    """Fetch a single document by path (relative to FS_BASE)."""
    r = requests.get(f"{FS_BASE}/{path}", params={"key": FB_API_KEY}, timeout=10)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


def main():
    out_dir = Path("backups")
    out_dir.mkdir(exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_file = out_dir / f"firestore_backup_{ts}.json"

    backup = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "project": FB_PROJECT,
        "collections": {},
        "special_docs": {},
    }

    total = 0
    for col in COLLECTIONS:
        print(f"  Exporting {col}...", end=" ", flush=True)
        try:
            docs = _list_collection(col)
            backup["collections"][col] = docs
            print(f"{len(docs)} docs")
            total += len(docs)
        except requests.HTTPError as e:
            print(f"ERROR: {e}")
            backup["collections"][col] = []

    # Special doc: sessions/ess-templates-config
    print("  Exporting sessions/ess-templates-config...", end=" ", flush=True)
    try:
        doc = _get_doc("sessions/ess-templates-config")
        backup["special_docs"]["sessions/ess-templates-config"] = doc
        print("ok" if doc else "not found")
    except requests.HTTPError as e:
        print(f"ERROR: {e}")
        backup["special_docs"]["sessions/ess-templates-config"] = None

    out_file.write_text(json.dumps(backup, indent=2, ensure_ascii=False))
    size_kb = out_file.stat().st_size / 1024
    print(f"\nBackup saved: {out_file}  ({size_kb:.1f} KB, {total} total documents)")


if __name__ == "__main__":
    print(f"Spark Meeting — Firestore Backup")
    print(f"Project: {FB_PROJECT}")
    print(f"Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(1)
    except Exception as e:
        print(f"\nFATAL: {e}")
        sys.exit(1)
