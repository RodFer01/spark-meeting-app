# Security & Bug Review — Spark Meeting App
> Reviewed: 2026-10-13 | Scope: `server.py` + `index.html` | Model: claude-sonnet-4-6

---

## Severity Legend
- **CRITICAL** — Exploitable in production right now, no attacker preconditions
- **HIGH** — Real vulnerability, requires specific conditions or timing
- **MEDIUM** — Logic bug or dormant failure with meaningful blast radius
- **LOW** — Code quality issue or minor inconsistency

---

## CRITICAL

### 1. Hardcoded JWT fallback secret (`server.py:60`)
```python
_JWT_SECRET = os.environ.get("JWT_SECRET", "spark-meeting-2026-default")
```
The fallback value `"spark-meeting-2026-default"` is visible in source. If `JWT_SECRET` is absent from the CF environment, **anyone can forge a token with `role: "admin"`** and pass `_verify_token` — full admin access to all endpoints.

**Fix:** Remove the default. Raise `RuntimeError` at startup if `JWT_SECRET` is not set.
```python
_JWT_SECRET = os.environ["JWT_SECRET"]  # crash early rather than run insecure
```

---

### 2. Credentials exposed in `manifest.yml`
The following secrets are committed in plaintext to `manifest.yml`:
- `AZURE_CLIENT_SECRET: "ZsZ8Q~Yor..."`
- `HANA_PASSWORD: "Digital@123"`
- `API_KEY: "dde-intel-batch-2026"`
- `DH_JWT_SECRET: "dh-sa-lac-2026-producao"`

Anyone with read access to the repo has full credentials to the HANA database, Azure app registration, and DH API.

**Fix:** Move all secrets to CF user-provided services or `cf set-env`. Remove from `manifest.yml`. Rotate the exposed credentials immediately.

---

## HIGH

### 3. Login ignores `approved` flag (`server.py:852`)
`auth_login` checks `password_hash` but never reads `user.get("approved")`. An admin who revokes a user via `PATCH /api/users/{id}/approve` with `approved: false` has no effect — the user can immediately log in again and get a valid 12-hour JWT.

**Fix:** Add after the password check:
```python
if not user.get("approved", True):
    raise HTTPException(status_code=403, detail="Account pending approval.")
```

---

### 4. HANA connection leak on exception (`server.py:147, 167, 177`)
`_hq`, `_hx`, and `_hbatch` open a connection and call `conn.close()` only on the happy path. Any exception in `cur.execute` leaks the connection permanently. Under sustained errors the HANA connection pool exhausts and all subsequent DB calls fail.

**Fix:** Wrap with `try/finally`:
```python
def _run():
    conn = _hana_conn()
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        rows = [_row_to_dict(cur.description, row) for row in cur.fetchall()]
        return rows
    finally:
        conn.close()
```
Apply the same pattern to `_hx` and `_hbatch`.

---

### 5. `batch_notify` HTTP timeout for batches > 1 email (`server.py:783`)
`_ess_send_email` polls `SPARK_EMAIL_JOBS` with 45 × 2s sleep = up to **90s per email**. `batch_notify` calls it sequentially per registration. A 10-person batch can hold the HTTP connection open for 900s, well past CF/nginx timeouts (~60-120s). The client receives a gateway timeout while emails are partially sent, with no way to know which ones went through.

**Fix:** Convert to a fire-and-forget async task. Accept the batch, queue the work, return a `jobId` immediately. Expose a `GET /api/jobs/{id}/status` endpoint for progress polling.

---

## MEDIUM

### 6. `_get_ess_template("default")` always misroutes intelligence emails (`server.py:1874`)
```python
ess_container, ess_slot = await _get_ess_template("default")
```
`"default"` is not a key in `_ESS_TEMPLATES` (keys are `confirmation_pt`, `rsvp_es`, etc.). The function falls back to `next(t for t in _ESS_TEMPLATES.values() if t.get("container"))` — which is whichever template happens to be first, typically the Portuguese confirmation container. Intelligence emails to AEs are sent through the wrong ESS channel.

> **Note:** This bug is intentionally preserved as-is per session constraints. Do not fix without explicit authorization.

---

### 7. `_classify_with_sem` error fallback missing `ae_email`, `flsm`, `ae_emails`, `flsms` (`server.py:1583`)
When `_classify_org` raises for a given org, the catch block returns:
```python
{"classification": "unknown", "open_opps": 0, ..., "ae": None, "region": None, "aes": [], "regions": []}
```
Missing: `ae_email`, `flsm`, `ae_emails`, `flsms`. The batch endpoint's fallback at line ~1682 includes them. The inconsistency causes frontend code reading `company.ae_email` to receive `undefined` on error, breaking the "Send to AE" email flow silently.

**Fix:** Add the missing keys to the fallback dict:
```python
result = {
    ..., "ae": None, "ae_email": None, "flsm": None,
    "aes": [], "ae_emails": [], "flsms": [], "regions": [],
}
```

---

### 8. Campaign contacts upload is non-atomic (`server.py:2294`)
```python
await _hx("DELETE FROM SPARK_CAMPAIGN_CONTACTS WHERE campaign_id = ?", (camp_id,))
for row in rows[1:]:
    await _hx("UPSERT ...", (...))
```
`DELETE` runs unconditionally before any insert. If any `_hx` call in the loop raises (HANA error, data-too-long, network drop), the campaign is left with zero contacts. There is no rollback and the old data is gone.

**Fix:** Collect all inserts, execute DELETE + all UPSERTs inside a single `_hbatch` call (one connection, one `commit`). Alternatively, use a staging approach: insert with a `pending` flag, swap atomically on success.

---

### 9. `_email_html` is defined but never called (`server.py:372`)
The branded email wrapper (SAP logo, blue header, CTA button) is defined in `_email_html` but `_build_email` returns `(subject, raw_html_fragment)` and never calls it. Registrants receiving confirmation, rejection, RSVP, and teams-link emails get an unstyled HTML fragment with no logo, no branded header, and no CTA button. The `cta_text` computed in `_build_email` is silently discarded.

**Fix:** In `_build_email`, call `_email_html(eyebrow, headline, body_fragment, cta_text, cta_url)` and return the result as the HTML body.

---

## LOW

### 10. Double `_check_api_key` in `import_registrations` (`server.py:1099, 1105`)
Auth is checked twice in the same endpoint. No security impact, but misleads readers.

**Fix:** Remove the duplicate call.

---

## Summary

| # | Severity | File | Line | Status |
|---|---|---|---|---|
| 1 | CRITICAL | server.py | 60 | **Fixed 2026-10-13** |
| 2 | CRITICAL | manifest.yml | 18-25 | **Fixed 2026-10-13** — credentials rotated |
| 3 | HIGH | server.py | 852 | **Fixed 2026-10-13** |
| 4 | HIGH | server.py | 147,167,177 | **Fixed 2026-10-13** |
| 5 | HIGH | server.py | 783 | Open — architectural change required |
| 6 | MEDIUM | server.py | 1874 | Intentionally preserved |
| 7 | MEDIUM | server.py | 1583 | **Fixed 2026-10-13** |
| 8 | MEDIUM | server.py | 2294 | **Fixed 2026-10-13** |
| 9 | MEDIUM | server.py | 372 | **Fixed 2026-10-13** |
| 10 | LOW | server.py | 1099 | **Fixed 2026-10-13** |

**Immediate priority:** Fix #1 (JWT fallback) and rotate credentials from `manifest.yml` (#2) before the next push.
