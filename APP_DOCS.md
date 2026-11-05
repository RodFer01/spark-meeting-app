# Spark Meeting — Application Documentation
> Last updated: 2026-10-13 | Stack: FastAPI + SAP HANA Cloud + Vanilla JS SPA

---

## What This App Does

Spark Meeting is an internal tool for the SAP Digital Hub LAC team to manage **Digital Discovery Expert Series (DDE)** and **SAP Spark Meeting** sessions. It handles:

- Session management (create, edit, publish)
- Registration intake (public form + Excel import)
- Email dispatch via ESS (SAP Event Subscription Service)
- Lead Intelligence — cross-references registrants with DH Portal (pipeline, installed base, contacts)
- Campaign contact matching (upload CRM lists, match to registrants)
- Analytics and reporting

**Audience:** SAP Solution Advisors (DSA team, LAC region). Not public — requires login.

---

## Infrastructure

| Item | Value |
|---|---|
| CF App Name | `spark-meeting` |
| CF Org / Space | `presalesbtplac` / `DSA` |
| URL | `https://spark-meeting.cfapps.us10-002.hana.ondemand.com` |
| Buildpack | `python_buildpack` |
| Memory | 256M |
| Instances | 1 |
| Stack | `cflinuxfs4` (⚠️ deprecating May 2027 → migrate to cflinuxfs5) |
| HANA Service | `digital_solution_advisor` (hana-cloud, plan hana) |
| Auth Service | `spark-meeting-auth` (XSUAA) |
| DH API | `https://dh-api.cfapps.us10-002.hana.ondemand.com` |

---

## Repository Structure

```
spark-meeting-app/
├── server.py              # FastAPI backend — all endpoints, HANA helpers, email logic
├── index.html             # Single-file SPA (~7000 lines) — all UI logic, styles, JS
├── manifest.yml           # CF push configuration — env vars, services, routes
├── requirements.txt       # Python deps: fastapi, uvicorn, hdbcli, openpyxl, bcrypt, PyJWT
├── ess_cookie_push.py     # Local helper: pushes ESS cookies from browser to server
├── backup_firestore.py    # One-off: exports Firestore data (used during HANA migration)
├── migrate_to_hana.py     # One-off: migrates Firestore backup → HANA tables
├── registration.html      # Public registration form (embedded/linked from session)
├── sessions-pt.html       # Public sessions listing (Portuguese)
├── setup-auth.html        # Admin setup utility
├── start.sh               # Local dev start script
├── backups/               # Firestore export JSONs (kept for rollback reference)
└── data/                  # Static data files
```

---

## Backend (`server.py`)

### Auth Model

- **JWT HS256** with 12-hour expiry (`_JWT_EXPIRY = 43200`)
- Token payload: `{sub, email, name, role, iat, exp}`
- Roles: `admin`, `co-admin`, `user`
- Hard-coded super-admin: `rodrigo.ribeiro.ferreira@sap.com` (bypasses role check)
- SSO: Azure Entra (`_AZURE_CLIENT_ID`, `_AZURE_TENANT_ID`) — callback at `/api/auth/sso/callback`

**Auth guards (used on endpoints):**
- `_check_api_key(request)` — accepts Bearer JWT OR `X-API-Key` header
- `_check_admin(request)` — requires role `admin` or `co-admin`
- `_check_super_admin(request)` — requires the hardcoded admin email

### HANA Connection

Two credential paths (checked in order):
1. Env vars: `HANA_HOST`, `HANA_PORT`, `HANA_USER`, `HANA_PASSWORD`
2. Local file: `~/.spark_hana_creds.json`

**Core DB helpers:**
- `_hq(sql, params)` → async SELECT → `list[dict]`
- `_hx(sql, params)` → async INSERT/UPDATE/DELETE → None
- `_hbatch(sql, param_list)` → async loop of executes in one connection → `int` (rows written)

> ⚠️ Known bug: `_hq`/`_hx`/`_hbatch` do not use `try/finally` — connections leak on exception. See `SECURITY_REVIEW.md #4`. **FIXED 2026-10-13.**

### HANA Tables

All tables prefixed `SPARK_` to avoid collisions with the DH App on the same HANA instance.

| Table | Contents |
|---|---|
| `SPARK_SESSIONS` | Session metadata (title, area, dates array, teamsUrl) |
| `SPARK_REGISTRATIONS` | All registrants; `data_json` holds full row; `email`, `session`, `attended` also indexed |
| `SPARK_USERS` | App user accounts; `data_json` holds full record including bcrypt `password_hash` |
| `SPARK_EMAIL_JOBS` | ESS send queue; also used to log intelligence email downloads |
| `SPARK_ESS_TEMPLATES` | ESS container/slot config per template key (overrides hardcoded defaults) |
| `SPARK_INTELLIGENCE_SNAPSHOTS` | Persisted results of `/api/intelligence` runs |
| `SPARK_ANALYTICS_CAMPAIGNS` | Uploaded CRM campaign JSON blobs |
| `SPARK_ANALYTICS_REGISTRATIONS` | Uploaded registration analytics JSON blobs |
| `SPARK_CAMPAIGN_CONTACTS` | Parsed contacts from uploaded campaign Excel files |

**Row pattern:** Most tables store the full JSON object in `data_json NCLOB` plus a few indexed columns for filtering. `_from_hana(row)` unpacks `data_json` and merges `id` back in.

### Email (ESS)

**Flow:**
1. Backend builds `(subject, html_fragment)` via `_build_email(reg, email_type)`
2. Calls `_get_template(email_type, lang)` → `(container_id, slot)` from `_ESS_TEMPLATES`
3. `_ess_send_email(to_email, name, subject, html, container, slot)`:
   - Creates a job in `SPARK_EMAIL_JOBS` (status=`pending`)
   - POSTs to `POST https://ess.int.sap/api/... ` using `_ESS_COOKIES` (maintained by `ess_cookie_push.py`)
   - Polls job status up to 45×2s (90s max)

**Template keys:** `confirmation_pt/es`, `rejection_pt/es`, `rsvp_pt/es`, `teams_link_pt/es`

**Language detection:** `_lang_from_reg(reg)` → `"pt"` for Brazil, `"es"` for all other countries.

> ⚠️ Known issue: `_email_html()` (branded wrapper with logo + CTA button) is defined but never called — registrants receive unstyled HTML fragments. See `SECURITY_REVIEW.md #9`. **FIXED 2026-10-13.**

### Intelligence Pipeline

`GET /api/intelligence?session=X&session=Y`

1. Loads registrations for selected sessions
2. Maps session area → DH L1 areas via `_SPARK_TO_L1` dict
3. Groups registrants by `organization`
4. For each org (max 10 concurrent via `asyncio.Semaphore`):
   - Calls DH API: `/api/outreach/contacts/search/{org}` → contacts + `account_bp`
   - Calls DH API: `/api/ae-analysis/installed-base/{account_bp}` → installed solutions
   - Calls DH API: `/api/pipeline?search={org}&sol_l1={l1}` → open opportunities
   - Classifies: `potential_lead` / `maturation` / `adoption` / `unknown`
5. Persists snapshot to `SPARK_INTELLIGENCE_SNAPSHOTS`
6. Returns enriched companies list with `participants`, `top_contacts`, `ae`, `flsm`, `pipeline`

DH API auth: service JWT signed with `DH_JWT_SECRET`, 30-minute expiry, role `viewer`.

### Campaign Contacts

`POST /api/campaigns/{camp_id}/contacts/upload` (Excel upload)

- Parses `.xlsx` with `openpyxl`
- Expected columns: `Email`, `First Name`, `Last Name`, `Planning Entity Name`, `Title`, `AE`, `LoB`, `SDE`, `Persona Name`, `Campaña`, `ERP`, `Link Prospects`
- Deletes existing rows for `camp_id`, inserts fresh (non-atomic — see `SECURITY_REVIEW.md #8`)

`GET /api/campaigns/match?email=&name=` — fuzzy match against loaded contacts.

---

## Frontend (`index.html`)

Single HTML file, ~7000 lines. No build step. Plain vanilla JS + inline CSS. Deployed as a static file served by FastAPI's `StaticFiles`.

### Page Structure

```
Login / Register / SSO
├── Sessions       — list + create/edit sessions
├── Registrations  — registrant table, filters, batch email, Excel import, Email AE
├── Reports        — charts (attendance, by country, by org)
├── Intelligence   — lead classification dashboard, snapshots, send-to-AE
├── Settings       — ESS template config, user management, activity log
└── Campaigns      — CRM contact lists, matching tool
```

### Key Global State

| Variable | Description |
|---|---|
| `_token` | JWT stored in `localStorage` |
| `_user` | `{name, email, role, modules}` decoded from token |
| `_sessions` | Session list loaded on login |
| `_registrations` | Full registrations array (loaded by `loadRegistrations()`) |
| `_intelData` | Last Intelligence run result (in-memory, cleared on new run) |
| `_regAeMap` | `{ orgName: {ae, ae_email, flsm} }` — rebuilt from `_intelData.companies` on each `renderRegistrations()` call |
| `_reportCharts` | Chart.js instances (destroyed on re-render to avoid leaks) |

### Auth Flow

1. `localStorage.getItem("spark_token")` on page load → `initApp()`
2. `initApp()` verifies token, loads sessions, routes to last page
3. Role gates: `admin-only` CSS class on elements; checked via `_user.role`

### Registration Import

Button triggers hidden `<input type="file" accept=".xlsx">`. Filename must match `^(.+)-(\d{2})_(\d{2})\.xlsx$` (e.g., `Session Name-21_09.xlsx`). Backend at `POST /api/registrations/import` parses, deduplicates by SHA1 of `email+session_slug`.

### FLSM / AE Enrichment (Registrations Page)

FLSM and AE are **not stored on registration records**. They come from Intelligence data. Enrichment is purely client-side:

1. `renderRegistrations()` rebuilds `_regAeMap` from `_intelData.companies` (if loaded)
2. FLSM/AE columns show `—` until user runs Intelligence for the session
3. Filters for FLSM/AE use `_regAeMap` for matching
4. "Email AE" batch button generates `.eml` files (RFC 2822, base64 HTML body) client-side via `Blob + <a download>`

---

## Local Development

```bash
# Install deps
pip install -r requirements.txt

# HANA credentials (used when HANA_HOST env var is absent)
cat > ~/.spark_hana_creds.json << 'EOF'
{"host": "...", "port": 443, "user": "DBADMIN", "password": "..."}
EOF

# Run
python server.py
# Opens on http://localhost:8000
```

---

## Deployment

```bash
cd /Users/I816087/Library/CloudStorage/OneDrive-SAPSE/projects/spark-meeting-app
cf login -a https://api.cf.us10-002.hana.ondemand.com
cf target -o presalesbtplac -s DSA
cf push spark-meeting
```

> **Rule:** Each `cf push` requires explicit per-session authorization. Do not push without confirming with the user first.

**After push, verify:**
- `GET /api/sessions` returns sessions
- `GET /api/registrations` returns registrants
- `GET /api/intelligence/snapshots` returns snapshot list (no 500)
- Login works, JWT issued

---

## ESS Cookie Maintenance

ESS cookies expire periodically. When emails start failing with 401/403:

1. Run `ess_cookie_push.py` locally (requires Chrome + valid ESS session)
2. It pushes fresh cookies to `POST /api/ess/cookies`
3. Check status at `GET /api/ess/status`

---

## ESS Worker

`ess_cookie_push.py` runs locally as a LaunchAgent (`com.sap.ess-cookie-push.plist`). It monitors the `SPARK_EMAIL_JOBS` table and dispatches pending jobs. To restart:

```bash
launchctl bootout gui/501 ~/Library/LaunchAgents/com.sap.ess-cookie-push.plist
launchctl bootstrap gui/501 ~/Library/LaunchAgents/com.sap.ess-cookie-push.plist
```

---

## Known Issues & Backlog

| Item | Severity | Notes |
|---|---|---|
| `batch_notify` HTTP timeout | HIGH | Sequential, up to 90s/email — architectural fix pending |
| `_get_ess_template("default")` misroutes | MEDIUM | Intentionally preserved bug |
| cflinuxfs4 deprecation | LOW | Migrate to cflinuxfs5 before May 2027 |
| Intelligence auto-load on page open | Backlog | Aggregate view not yet implemented |
| Settings — Activity Log improvements | Backlog | List Sources tab pending |

**Fixed 2026-10-13:** Secrets in manifest.yml (CRITICAL), JWT fallback (CRITICAL), login ignored `approved` flag (HIGH), HANA connection leak (HIGH), `_classify_with_sem` fallback dict (MEDIUM), `_email_html` never called (MEDIUM), campaign upload non-atomic (MEDIUM), duplicate `_check_api_key` in `import_registrations` (LOW).

See `SECURITY_REVIEW.md` for detailed descriptions and fix guidance.

---

## Integration Points

| System | How | Auth |
|---|---|---|
| SAP HANA Cloud | `hdbcli` direct connection | DBADMIN credentials via env vars |
| DH App API | `httpx` server-to-server | Service JWT signed with `DH_JWT_SECRET` |
| ESS (SAP Event Subscription Service) | `httpx` REST | Browser cookies pushed by `ess_cookie_push.py` |
| Azure Entra (SSO) | OAuth2 redirect | `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` |
