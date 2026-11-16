#!/usr/bin/env python3
"""Spark Meeting — static server + shared auth endpoint + sessions REST API."""
import os, json, time, asyncio, hashlib, re, unicodedata
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from fastapi import FastAPI, HTTPException, Request, Body, UploadFile, File, Form, Query
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import bcrypt
import jwt as pyjwt
import uvicorn
import uuid as _uuid

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import urllib.request
from spark_db import _hq, _hx, _hbatch, _hx_txn, _from_hana, _upsert_reg, _upsert_user, _hana_is_dup


def _hana_oauth_token(uaa: dict) -> str:
    """Fetch OAuth access token from UAA using client_credentials grant."""
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


# ── API key protection ─────────────────────────────────────────────────────────
_API_KEY    = os.environ.get("API_KEY", "")
_ADMIN_EMAIL = "rodrigo.ribeiro.ferreira@sap.com"

# Email type → boolean field name
_FLAG_FIELD = {
    "confirmation": "confirmationSent",
    "rejection":    "rejectionSent",
    "rsvp":         "rsvpSent",
    "teams_link":   "teamsLinkSent",
}

# ── Azure Entra SSO ───────────────────────────────────────────────────────────
_AZURE_CLIENT_ID     = os.environ.get("AZURE_CLIENT_ID", "8e021f91-be5d-4173-b6ff-23c5ec893533")
_AZURE_TENANT_ID     = os.environ.get("AZURE_TENANT_ID", "42f7676c-f455-423c-82f6-dc2d99791af7")
_AZURE_CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", "")

# ── Auth (HANA + bcrypt + HS256 JWT) ─────────────────────────────────────────
_JWT_SECRET = os.environ.get("JWT_SECRET") or ""
if not _JWT_SECRET:
    raise RuntimeError("JWT_SECRET env var is required and must not be empty")
_JWT_EXPIRY = 43200  # 12 hours

def _hash_pw(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def _check_pw(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False

def _make_token(user_id: str, email: str, name: str, role: str = "user") -> str:
    now = int(time.time())
    return pyjwt.encode(
        {"sub": user_id, "email": email, "name": name, "role": role, "iat": now, "exp": now + _JWT_EXPIRY},
        _JWT_SECRET, algorithm="HS256",
    )

def _verify_token(token: str) -> dict:
    try:
        return pyjwt.decode(token, _JWT_SECRET, algorithms=["HS256"])
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# ── ESS email transport ────────────────────────────────────────────────────────
_ESS_BASE    = "https://ess.int.sap"
_SITE_URL    = "https://digital-discover-expert-series-esp-5e2d.sites-sap.com"
_ESS_COOKIES: dict   = {}
_ESS_COOKIES_AT: str = ""
_batch_jobs:  dict   = {}  # in-memory job tracker for async batch sends

_TEMPLATE_KEYS = [
    "confirmation_pt", "confirmation_es",
    "rejection_pt",    "rejection_es",
    "rsvp_pt",         "rsvp_es",
    "teams_link_pt",   "teams_link_es",
]
_PT_CONTAINER = "9d3ca299-9bcb-431d-9a44-582711eb20ea"  # SAP Spark Meeeting - PT
_ES_CONTAINER = "c0f0e1e7-8cfe-49f2-8812-b9c367a4cbc2"  # SAP Spark Meeeting - ES
_ESS_TEMPLATES: dict = {
    "confirmation_pt": {"container": _PT_CONTAINER, "slot": "body"},
    "confirmation_es": {"container": _ES_CONTAINER, "slot": "body"},
    "rejection_pt":    {"container": _PT_CONTAINER, "slot": "body"},
    "rejection_es":    {"container": _ES_CONTAINER, "slot": "body"},
    "rsvp_pt":         {"container": _PT_CONTAINER, "slot": "body"},
    "rsvp_es":         {"container": _ES_CONTAINER, "slot": "body"},
    "teams_link_pt":   {"container": _PT_CONTAINER, "slot": "body"},
    "teams_link_es":   {"container": _ES_CONTAINER, "slot": "body"},
}


async def _load_templates_from_hana() -> None:
    global _ESS_TEMPLATES
    try:
        rows = await _hq("SELECT key, container, slot FROM SPARK_ESS_TEMPLATES", ())
        for row in rows:
            key = row.get("key", "")
            if key in _TEMPLATE_KEYS:
                _ESS_TEMPLATES[key] = {
                    "container": row.get("container", ""),
                    "slot": row.get("slot", "body") or "body",
                }
    except Exception:
        pass  # non-fatal — use hardcoded defaults


@asynccontextmanager
async def lifespan(app):
    await _load_templates_from_hana()
    yield


app = FastAPI(title="Spark Meeting", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


def _get_caller_email(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        try:
            return _verify_token(auth[7:]).get("email", "")
        except Exception:
            pass
    return ""

def _check_api_key(request: Request):
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        _verify_token(auth[7:])
        return
    if not _API_KEY:
        return
    if request.headers.get("X-API-Key", "") != _API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header.")

def _check_admin(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=403, detail="Admin access required.")
    payload = _verify_token(auth[7:])
    role = payload.get("role", "user")
    email = payload.get("email", "").lower()
    if role not in ("admin", "co-admin") and email != _ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Admin access required.")

def _check_super_admin(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=403, detail="Super-admin access required.")
    payload = _verify_token(auth[7:])
    if payload.get("email", "").lower() != _ADMIN_EMAIL:
        raise HTTPException(status_code=403, detail="Super-admin access required.")


# ── Sessions endpoints ─────────────────────────────────────────────────────────
@app.get("/api/sessions")
async def list_sessions(request: Request, available_from: str = "2026-09-01"):
    _check_api_key(request)
    rows = await _hq("SELECT id, data_json FROM SPARK_SESSIONS ORDER BY id LIMIT 500", ())
    docs = [_from_hana(r) for r in rows]
    if available_from:
        docs = [d for d in docs if any(
            (dt.get("date","") if isinstance(dt, dict) else dt) >= available_from
            for dt in (d.get("dates") or [])
        )]
    return docs

@app.post("/api/sessions", status_code=201)
async def create_session(request: Request, body: Any = Body(...)):
    _check_api_key(request)
    data = body if isinstance(body, dict) else {}
    doc_id = data.get("id") or _uuid.uuid4().hex
    data["id"] = doc_id
    title = str(data.get("title", "") or "")
    area  = str(data.get("area", "") or "")[:128]
    now_ts = datetime.now(timezone.utc).isoformat()
    await _hx(
        "UPSERT SPARK_SESSIONS (id, title, area, data_json, updated_at) VALUES (?, ?, ?, ?, ?) WITH PRIMARY KEY",
        (doc_id, title, area, json.dumps(data), now_ts)
    )
    return data

@app.put("/api/sessions/{session_id}")
async def update_session(session_id: str, request: Request, body: Any = Body(...)):
    _check_api_key(request)
    data = body if isinstance(body, dict) else {}
    data["id"] = session_id
    title = str(data.get("title", "") or "")
    area  = str(data.get("area", "") or "")[:128]
    now_ts = datetime.now(timezone.utc).isoformat()
    await _hx(
        "UPSERT SPARK_SESSIONS (id, title, area, data_json, updated_at) VALUES (?, ?, ?, ?, ?) WITH PRIMARY KEY",
        (session_id, title, area, json.dumps(data), now_ts)
    )
    return data

@app.delete("/api/sessions/{session_id}", status_code=204)
async def delete_session(session_id: str, request: Request):
    _check_admin(request)
    await _hx("DELETE FROM SPARK_SESSIONS WHERE id = ?", (session_id,))


# ── Registrations endpoints ────────────────────────────────────────────────────
@app.post("/api/registrations", status_code=201)
async def create_registration(body: Any = Body(...)):
    data = body if isinstance(body, dict) else {}
    data["registeredAt"] = datetime.now(timezone.utc).isoformat()
    doc_id = data.get("id") or _uuid.uuid4().hex
    data["id"] = doc_id
    await _upsert_reg(doc_id, data)
    return data

@app.patch("/api/registrations/{reg_id}")
async def patch_registration(reg_id: str, request: Request, body: Any = Body(...)):
    _check_api_key(request)
    updates = body if isinstance(body, dict) else {}
    rows = await _hq("SELECT id, data_json FROM SPARK_REGISTRATIONS WHERE id = ?", (reg_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="Registration not found")
    reg = _from_hana(rows[0])
    reg.update(updates)
    reg["id"] = reg_id
    await _upsert_reg(reg_id, reg)
    return reg

@app.get("/api/registrations")
async def list_registrations(request: Request):
    _check_api_key(request)
    rows = await _hq("SELECT id, data_json FROM SPARK_REGISTRATIONS LIMIT 10000", ())
    return [_from_hana(r) for r in rows]

@app.delete("/api/registrations/{reg_id}", status_code=204)
async def delete_registration(reg_id: str, request: Request):
    _check_api_key(request)
    await _hx("DELETE FROM SPARK_REGISTRATIONS WHERE id = ?", (reg_id,))


@app.post("/api/registrations/enrich-domains")
async def enrich_registrations_by_domain(request: Request, body: Any = Body(default={})):
    """Enrich registrations with company name, AE, FLSM, SDE from pipeline via email domain.

    Iterates all registrations (or filtered by session), extracts each email domain,
    calls dh-api /api/outreach/contacts/by-domain/{domain}, and patches data_json with:
      organization (corrected), ae, ae_email, flsm, sde.

    Body (optional):
      session     — filter to a specific session title
      overwrite   — if false (default), only fill blank fields; if true, always overwrite
    """
    _check_api_key(request)

    session_filter = body.get("session") if isinstance(body, dict) else None
    overwrite      = bool((body.get("overwrite", False)) if isinstance(body, dict) else False)

    if session_filter:
        rows = await _hq(
            "SELECT id, data_json FROM SPARK_REGISTRATIONS WHERE data_json LIKE ? LIMIT 10000",
            (f'%{session_filter}%',),
        )
    else:
        rows = await _hq("SELECT id, data_json FROM SPARK_REGISTRATIONS LIMIT 10000", ())

    regs = [_from_hana(r) for r in rows]

    # Collect unique domains (skip personal/public email providers)
    domain_map: dict[str, dict | None] = {}  # domain → dh-api result (lazily populated)
    for reg in regs:
        email = (reg.get("email") or "").strip().lower()
        if "@" in email:
            domain = email.split("@", 1)[1]
            if domain and domain not in _PERSONAL and domain not in domain_map:
                domain_map[domain] = None

    # Resolve each domain against dh-api (bounded concurrency: 5 at a time)
    sem = asyncio.Semaphore(5)

    async def _resolve(c: httpx.AsyncClient, domain: str) -> tuple[str, dict | None]:
        async with sem:
            result = await _dh_get(c, f"/api/outreach/contacts/by-domain/{domain}")
            if isinstance(result, dict) and result.get("match"):
                return domain, result["match"]
            return domain, None

    async with httpx.AsyncClient() as c:
        tasks = [_resolve(c, d) for d in domain_map]
        results = await asyncio.gather(*tasks)

    for domain, match in results:
        domain_map[domain] = match

    # Patch registrations
    enriched = 0
    skipped  = 0
    not_found = 0
    detail: list[dict] = []

    for reg in regs:
        email = (reg.get("email") or "").strip().lower()
        if "@" not in email:
            skipped += 1
            continue

        domain = email.split("@", 1)[1]
        match  = domain_map.get(domain)

        if not match:
            not_found += 1
            detail.append({"id": reg.get("id"), "email": email, "status": "no_match"})
            continue

        updates: dict = {}
        # Only update org name when domain root clearly belongs to the matched company.
        # Partners/consultants may be registered under client accounts in Outreach,
        # so we require the domain root (e.g. "jan" from "jan.com.br") to appear in
        # the matched account_name. This avoids overwriting correct self-reported names.
        account_name = match.get("account_name") or ""
        domain_root  = domain.split(".")[0].lower()
        org_match_confident = len(domain_root) >= 3 and domain_root in account_name.lower()
        if org_match_confident and (overwrite or not reg.get("organization")):
            updates["organization"] = account_name
        if overwrite or not reg.get("ae"):
            updates["ae"]       = match.get("ae_name")
            updates["ae_email"] = match.get("ae_email")
        if overwrite or not reg.get("flsm"):
            updates["flsm"] = match.get("flsm")
        if overwrite or not reg.get("sde"):
            updates["sde"]  = match.get("sde")

        if not any(v for v in updates.values()):
            skipped += 1
            continue

        reg_id  = reg.get("id") or reg.get("_id")
        patched = {**reg, **updates}
        patched.pop("_id", None)
        await _upsert_reg(reg_id, patched)
        enriched += 1
        detail.append({
            "id":           reg_id,
            "email":        email,
            "status":       "enriched",
            "organization": updates.get("organization"),
            "ae":           updates.get("ae"),
            "flsm":         updates.get("flsm"),
            "sde":          updates.get("sde"),
        })

    return {
        "ok":        True,
        "enriched":  enriched,
        "skipped":   skipped,
        "not_found": not_found,
        "total":     len(regs),
        "detail":    detail,
    }


@app.get("/api/ics/{reg_id}")
async def get_ics(reg_id: str):
    rows = await _hq("SELECT id, data_json FROM SPARK_REGISTRATIONS WHERE id = ?", (reg_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="Registration not found")
    reg = _from_hana(rows[0])
    reg["_id"] = reg_id
    teams_url = reg.get("teamsUrl", "")
    ics_content = _generate_ics(reg, teams_url)
    from fastapi.responses import Response
    return Response(
        content=ics_content,
        media_type="text/calendar; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="session-{reg_id}.ics"'},
    )


# ── Email helpers ──────────────────────────────────────────────────────────────
def _email_html(eyebrow: str, headline: str, body_html: str, cta_text: str, cta_url: str) -> str:
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width">
<style>body{{margin:0;padding:0;background:#f5f6f7}}a{{color:#0057d2}}</style></head>
<body style="margin:0;padding:0;background:#f5f6f7">
<center>
<table width="640" border="0" cellpadding="0" cellspacing="0" style="max-width:640px;background:#fff;font-family:Arial,Helvetica,sans-serif">
  <tr><td style="padding:24px 48px">
    <img src="https://www.sap.com/content/dam/application/shared/logos/SAP_Logo.png" alt="SAP" height="28" style="height:28px;width:auto">
  </td></tr>
  <tr><td style="background:#0057d2;padding:40px 48px">
    <div style="font-size:12px;font-weight:bold;text-transform:uppercase;color:#ebf8ff;letter-spacing:.08em;margin-bottom:12px">{eyebrow}</div>
    <div style="font-size:26px;font-weight:bold;color:#ffffff;line-height:1.2">{headline}</div>
  </td></tr>
  <tr><td style="padding:40px 48px;font-size:14px;line-height:1.6;color:#223548">
    {body_html}
    {"<br><br><table border='0' cellpadding='0' cellspacing='0'><tr><td style='background:#0057d2;border-radius:6px;padding:12px 24px'><a href='" + cta_url + "' style='color:#fff;font-size:15px;font-weight:bold;text-decoration:none'>" + cta_text + "</a></td></tr></table>" if cta_text else ""}
  </td></tr>
  <tr><td style="background:#eaecee;padding:32px 48px;font-size:12px;color:#556b8a;line-height:1.5">
    <img src="https://www.sap.com/dam/application/shared/logos/sap-group/sap-tagline-straight-r-grad-blu.png" alt="SAP" height="24" style="height:24px;margin-bottom:16px;display:block">
    Este e-mail foi enviado por SAP Digital Hub. Se não deseja mais receber comunicações,
    <a href="https://www.sap.com/dashboard/marketing-preferences.html" style="color:#556b8a">gerencie suas preferências</a>.
    <br>© SAP SE. Todos os direitos reservados.
  </td></tr>
</table>
</center>
</body></html>"""


async def _teams_url_from_session(session_name: str, session_date: str = "") -> str:
    if not session_name:
        return ""
    rows = await _hq("SELECT id, data_json FROM SPARK_SESSIONS LIMIT 500", ())
    for row in rows:
        d = _from_hana(row)
        if d.get("title") != session_name:
            continue
        dates = d.get("dates", [])
        if isinstance(dates, list):
            if session_date:
                for entry in dates:
                    if isinstance(entry, dict) and entry.get("date") == session_date:
                        link = entry.get("meetingLink", "")
                        if link:
                            return link
            for entry in dates:
                if isinstance(entry, dict):
                    link = entry.get("meetingLink", "")
                    if link:
                        return link
        return d.get("teamsUrl", "") or ""
    return ""


def _lang_from_reg(reg: dict) -> str:
    country = (reg.get("country") or "").strip().lower()
    if country in ("brasil", "brazil"):
        return "pt"
    if country:
        return "es"
    # Fall back to stored language field if country is missing
    return reg.get("lang") or reg.get("language", "pt")


def _generate_ics(reg: dict, teams_url: str) -> str:
    """Generate RFC 5545 .ics content for a registration's session."""
    import re
    uid = reg.get("_id") or reg.get("id") or "spark-meeting"
    session = reg.get("session", "Digital Discovery Expert Series")
    date_raw = (reg.get("sessionDate") or reg.get("date") or "").strip()
    # Try to parse a date like "DD/MM/YYYY" or "YYYY-MM-DD"; fall back to today
    try:
        if re.match(r"\d{2}/\d{2}/\d{4}", date_raw):
            d, m, y = date_raw.split("/")
            dt_start = f"{y}{m}{d}T100000Z"
            dt_end   = f"{y}{m}{d}T120000Z"
        elif re.match(r"\d{4}-\d{2}-\d{2}", date_raw):
            dt_start = date_raw.replace("-", "") + "T100000Z"
            dt_end   = date_raw.replace("-", "") + "T120000Z"
        else:
            raise ValueError("unrecognised date")
    except Exception:
        from datetime import datetime
        today = datetime.utcnow().strftime("%Y%m%d")
        dt_start = f"{today}T100000Z"
        dt_end   = f"{today}T120000Z"
    description = f"Link Teams: {teams_url}" if teams_url else session
    return "\r\n".join([
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//SAP//SparkMeeting//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
        "BEGIN:VEVENT",
        f"UID:{uid}@spark-meeting.sap",
        f"SUMMARY:{session}",
        f"DTSTART:{dt_start}",
        f"DTEND:{dt_end}",
        f"DESCRIPTION:{description}",
        f"URL:{teams_url}" if teams_url else "URL:https://spark-meeting.cfapps.us10-002.hana.ondemand.com",
        "END:VEVENT",
        "END:VCALENDAR",
    ]) + "\r\n"


def _build_email(reg: dict, email_type: str) -> tuple[str, str]:
    lang     = _lang_from_reg(reg)
    name     = reg.get("name", "")
    email    = reg.get("email", "")
    session  = reg.get("session", "")
    date_raw = reg.get("sessionDate", "") or reg.get("date", "")
    # Format as DD/MM/YYYY for display
    if date_raw and len(date_raw) == 10 and date_raw[4] == "-":
        date = f"{date_raw[8:10]}/{date_raw[5:7]}/{date_raw[0:4]}"
    else:
        date = date_raw
    time_str = "10:00 BRT · São Paulo" if lang == "pt" else "11:00 COL · 12:00 ARG · 09:00 MX"
    site     = _SITE_URL
    teams_url = reg.get("_teamsUrl", "") or reg.get("teamsUrl", "")

    if email_type == "confirmation":
        if lang == "pt":
            subject  = "Inscrição Confirmada – Digital Discovery Expert Series"
            eyebrow  = "CONFIRMADO"
            headline = "Sua inscrição está confirmada!"
            body     = f"""Olá, <strong>{name}</strong>!<br><br>
Sua inscrição no <strong>Digital Discovery Expert Series</strong> foi confirmada. Ficamos felizes em ter você conosco!<br><br>
<table border="0" cellpadding="0" cellspacing="0" style="background:#f0f6ff;border-left:4px solid #0057d2;border-radius:4px;padding:16px 20px">
  <tr><td style="font-size:13px;color:#223548;line-height:1.8">
    <strong>Sessão:</strong> {session}<br>
    <strong>Data:</strong> {date}<br>
    <strong>Horário:</strong> {time_str}
  </td></tr>
</table><br>
Em breve você receberá o link de acesso. Fique atento ao seu e-mail!"""
            cta_text = "Ver Agenda Completa"
            cta_url  = site
        else:
            subject  = "Inscripción Confirmada – Digital Discovery Expert Series"
            eyebrow  = "CONFIRMADO"
            headline = "¡Tu inscripción está confirmada!"
            body     = f"""Hola, <strong>{name}</strong>!<br><br>
Tu inscripción en el <strong>Digital Discovery Expert Series</strong> fue confirmada exitosamente. ¡Nos alegra tenerte con nosotros!<br><br>
<table border="0" cellpadding="0" cellspacing="0" style="background:#f0f6ff;border-left:4px solid #0057d2;border-radius:4px;padding:16px 20px">
  <tr><td style="font-size:13px;color:#223548;line-height:1.8">
    <strong>Sesión:</strong> {session}<br>
    <strong>Fecha:</strong> {date}<br>
    <strong>Horario:</strong> {time_str}
  </td></tr>
</table><br>
Pronto recibirás el enlace de acceso. ¡Mantente atento a tu correo!"""
            cta_text = "Ver Agenda Completa"
            cta_url  = site

    elif email_type == "rejection":
        if lang == "pt":
            subject  = "Sobre sua inscrição – Digital Discovery Expert Series"
            eyebrow  = "AVISO"
            headline = "Não foi possível confirmar seu registro"
            body     = f"""Olá, <strong>{name}</strong>!<br><br>
Agradecemos seu interesse no <strong>Digital Discovery Expert Series</strong>.<br><br>
Infelizmente, as sessões deste programa são destinadas exclusivamente a <strong>profissionais de organizações</strong>.
O e-mail utilizado no cadastro (<em>{email}</em>) não corresponde a um domínio corporativo, por isso não foi possível confirmar sua inscrição.<br><br>
Caso acredite que houve um engano ou deseje se inscrever com um e-mail corporativo, acesse o link abaixo."""
            cta_text = "Tentar Novamente"
            cta_url  = site
        else:
            subject  = "Sobre tu inscripción – Digital Discovery Expert Series"
            eyebrow  = "AVISO"
            headline = "No fue posible confirmar tu registro"
            body     = f"""Hola, <strong>{name}</strong>!<br><br>
Gracias por tu interés en el <strong>Digital Discovery Expert Series</strong>.<br><br>
Lamentablemente, las sesiones de este programa están destinadas exclusivamente a <strong>profesionales de organizaciones</strong>.
El correo utilizado en el registro (<em>{email}</em>) no corresponde a un dominio corporativo, por lo que no fue posible confirmar tu inscripción.<br><br>
Si crees que hubo un error o deseas registrarte con un correo corporativo, accede al enlace a continuación."""
            cta_text = "Intentar de Nuevo"
            cta_url  = site

    elif email_type == "teams_link":
        reg_id    = reg.get("_id", "")
        app_base  = "https://spark-meeting.cfapps.us10-002.hana.ondemand.com"
        ics_url   = f"{app_base}/api/ics/{reg_id}" if reg_id else ""
        btn_style = ("display:inline-block;padding:12px 28px;background:#0070F2;color:#ffffff;"
                     "text-decoration:none;border-radius:6px;font-weight:700;font-size:14px;margin:4px 0")
        ics_style = ("display:inline-block;padding:10px 22px;background:#f0f6ff;color:#0070F2;"
                     "text-decoration:none;border-radius:6px;font-weight:600;font-size:13px;"
                     "border:1px solid #0070F2;margin:4px 0")
        if lang == "pt":
            subject  = "Seu link de acesso – Digital Discovery Expert Series"
            eyebrow  = "ACESSO CONFIRMADO"
            headline = "Sua sessão está chegando!"
            cta_text = ""
            cta_url  = ""
            body     = f"""Olá, <strong>{name}</strong>! Sua sessão está chegando.<br><br>
<table border="0" cellpadding="0" cellspacing="0" style="background:#f0f6ff;border-left:4px solid #0057d2;border-radius:4px;padding:16px 20px;margin-bottom:16px">
  <tr><td style="font-size:13px;color:#223548;line-height:1.8">
    <strong>Sessão:</strong> {session}<br>
    <strong>Data:</strong> {date}<br>
    <strong>Horário:</strong> {time_str}
  </td></tr>
</table>
<a href="{teams_url}" style="{btn_style}">Entrar na Reunião Teams</a><br><br>
{f'<a href="{ics_url}" style="{ics_style}">&#128197; Adicionar ao Calendário (.ics)</a>' if ics_url else ''}"""
        else:
            subject  = "Tu enlace de acceso – Digital Discovery Expert Series"
            eyebrow  = "ACCESO CONFIRMADO"
            headline = "¡Tu sesión se acerca!"
            cta_text = ""
            cta_url  = ""
            body     = f"""Hola, <strong>{name}</strong>! Tu sesión se acerca.<br><br>
<table border="0" cellpadding="0" cellspacing="0" style="background:#f0f6ff;border-left:4px solid #0057d2;border-radius:4px;padding:16px 20px;margin-bottom:16px">
  <tr><td style="font-size:13px;color:#223548;line-height:1.8">
    <strong>Sesión:</strong> {session}<br>
    <strong>Fecha:</strong> {date}<br>
    <strong>Horario:</strong> {time_str}
  </td></tr>
</table>
<a href="{teams_url}" style="{btn_style}">Unirse a la Reunión Teams</a><br><br>
{f'<a href="{ics_url}" style="{ics_style}">&#128197; Agregar al Calendario (.ics)</a>' if ics_url else ''}"""

    else:  # rsvp
        btn_style = ("display:inline-block;padding:12px 28px;background:#0070F2;color:#ffffff;"
                     "text-decoration:none;border-radius:6px;font-weight:700;font-size:14px;margin:4px 0")
        if lang == "pt":
            if teams_url:
                link_block = (
                    '<strong>Link de acesso:</strong><br><br>'
                    '<a href="' + teams_url + '" style="' + btn_style + '">Entrar na Reunião Teams</a><br><br>'
                )
            else:
                link_block = "O link de acesso será enviado por e-mail antes da sessão.<br><br>"
            subject  = "RSVP Confirmado – Digital Discovery Expert Series"
            eyebrow  = "LEMBRETE"
            headline = "Sua sessão está chegando!"
            cta_text = ""
            cta_url  = ""
            body     = f"""Olá, <strong>{name}</strong>!<br><br>
Este é um lembrete para a seguinte sessão.<br><br>
<table border="0" cellpadding="0" cellspacing="0" style="background:#f0f6ff;border-left:4px solid #0057d2;border-radius:4px;padding:16px 20px">
  <tr><td style="font-size:13px;color:#223548;line-height:1.8">
    <strong>Sessão:</strong> {session}<br>
    <strong>Data:</strong> {date}<br>
    <strong>Horário:</strong> {time_str}
  </td></tr>
</table><br>
{link_block}"""
        else:
            if teams_url:
                link_block = (
                    '<strong>Enlace de acceso:</strong><br><br>'
                    '<a href="' + teams_url + '" style="' + btn_style + '">Unirse a la Reunión Teams</a><br><br>'
                )
            else:
                link_block = "El enlace de acceso será enviado por correo antes de la sesión.<br><br>"
            subject  = "RSVP Confirmado – Digital Discovery Expert Series"
            eyebrow  = "RECORDATORIO"
            headline = "¡Tu sesión se acerca!"
            cta_text = ""
            cta_url  = ""
            body     = f"""Hola, <strong>{name}</strong>!<br><br>
Este es un recordatorio para la siguiente sesión.<br><br>
<table border="0" cellpadding="0" cellspacing="0" style="background:#f0f6ff;border-left:4px solid #0057d2;border-radius:4px;padding:16px 20px">
  <tr><td style="font-size:13px;color:#223548;line-height:1.8">
    <strong>Sesión:</strong> {session}<br>
    <strong>Fecha:</strong> {date}<br>
    <strong>Horario:</strong> {time_str}
  </td></tr>
</table><br>
{link_block}"""

    return subject, body


def _get_template(email_type: str, lang: str) -> tuple[str, str]:
    """Return (container_id, slot_id) for the given type+lang, with pt fallback."""
    key = f"{email_type}_{lang}"
    tmpl = _ESS_TEMPLATES.get(key) or _ESS_TEMPLATES.get(f"{email_type}_pt", {})
    container = tmpl.get("container", "")
    slot      = tmpl.get("slot", "body")
    if not container:
        raise RuntimeError(
            f"Template ESS não configurado para {email_type}/{lang}. "
            "Configure em Configurações ESS no backoffice."
        )
    return container, slot


async def _ess_send_email(to_addr: str, to_name: str, subject: str, html: str,
                          container: str, slot: str) -> None:
    job_id = _uuid.uuid4().hex
    now_ts = datetime.now(timezone.utc).isoformat()
    await _hx(
        "UPSERT SPARK_EMAIL_JOBS (id, status, to_email, to_name, subject, html, container, slot, "
        "created_at, updated_at, from_email, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) WITH PRIMARY KEY",
        (job_id, "pending", to_addr, to_name, subject, html, container, slot, now_ts, now_ts, "", "")
    )
    for _ in range(45):
        await asyncio.sleep(2)
        rows = await _hq("SELECT status, error FROM SPARK_EMAIL_JOBS WHERE id = ?", (job_id,))
        if not rows:
            continue
        status = rows[0].get("status", "")
        error  = rows[0].get("error", "") or ""
        if hasattr(error, 'read'):
            error = error.read()
        if status == "sent":
            return
        if status == "failed":
            raise RuntimeError(error or "ESS worker reported failure")
    raise RuntimeError("Email job timed out — verifique se o ess_worker.py está rodando no Mac")


# ── Notify endpoint ────────────────────────────────────────────────────────────
@app.post("/api/registrations/{reg_id}/notify")
async def notify_registration(reg_id: str, request: Request, body: Any = Body(...)):
    _check_api_key(request)
    payload = body if isinstance(body, dict) else {}
    email_type = payload.get("type")
    if email_type not in ("confirmation", "rejection", "rsvp", "teams_link"):
        raise HTTPException(status_code=400, detail="type must be: confirmation, rejection, rsvp, or teams_link")
    teams_url = payload.get("teamsUrl", "")
    rows = await _hq("SELECT id, data_json FROM SPARK_REGISTRATIONS WHERE id = ?", (reg_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="Registration not found")
    reg = _from_hana(rows[0])
    reg["_id"] = reg_id
    if email_type == "teams_link" and not teams_url:
        teams_url = await _teams_url_from_session(
            reg.get("session", ""),
            reg.get("sessionDate", "") or reg.get("date", ""),
        )
    if teams_url:
        reg["_teamsUrl"] = teams_url
        reg["teamsUrl"] = teams_url
        await _upsert_reg(reg_id, reg)
    elif email_type == "teams_link":
        session_name = reg.get("session", "")
        raise HTTPException(status_code=422,
            detail=f"Teams URL não encontrado para a sessão '{session_name}'. "
                   "Configure meetingLink nas datas da sessão ou o campo teamsUrl.")
    to_email = reg.get("email", "")
    if not to_email:
        raise HTTPException(status_code=400, detail="Registration has no email address")
    lang = _lang_from_reg(reg)
    subject, html = _build_email(reg, email_type)
    try:
        container, slot = _get_template(email_type, lang)
        await _ess_send_email(to_email, reg.get("name", ""), subject, html, container, slot)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Email send failed: {exc}")
    flag_field = _FLAG_FIELD.get(email_type)
    if flag_field:
        reg[flag_field] = True
        await _upsert_reg(reg_id, reg)
    return {"ok": True, "type": email_type, "to": to_email}


# ── ESS cookie management endpoints ───────────────────────────────────────────
@app.post("/api/ess/cookies")
async def ess_push_cookies(request: Request, body: Any = Body(...)):
    global _ESS_COOKIES, _ESS_COOKIES_AT
    _check_api_key(request)
    cookies = (body or {}).get("cookies", {}) if isinstance(body, dict) else {}
    if not isinstance(cookies, dict):
        raise HTTPException(status_code=400, detail="cookies must be a dict")
    _ESS_COOKIES = cookies
    _ESS_COOKIES_AT = datetime.now(timezone.utc).isoformat()
    return {"ok": True, "cookie_count": len(_ESS_COOKIES), "updated_at": _ESS_COOKIES_AT}

@app.get("/api/ess/status")
async def ess_status(request: Request):
    _check_api_key(request)
    configured = [k for k, v in _ESS_TEMPLATES.items() if v.get("container")]
    return {
        "cookie_count":        len(_ESS_COOKIES),
        "updated_at":          _ESS_COOKIES_AT or None,
        "templates_configured": configured,
        "templates_total":      len(_TEMPLATE_KEYS),
    }

# ── ESS template config endpoints ─────────────────────────────────────────────
@app.get("/api/ess/templates")
async def get_ess_templates(request: Request):
    _check_api_key(request)
    return _ESS_TEMPLATES

@app.post("/api/ess/templates")
async def save_ess_templates(request: Request, body: Any = Body(...)):
    global _ESS_TEMPLATES
    _check_api_key(request)
    data = body if isinstance(body, dict) else {}
    for key in _TEMPLATE_KEYS:
        if key in data and isinstance(data[key], dict):
            _ESS_TEMPLATES[key] = {
                "container": str(data[key].get("container", "")),
                "slot":      str(data[key].get("slot", "body")) or "body",
            }
    hana_error = None
    try:
        param_list = [(k, v["container"], v.get("slot", "body"))
                      for k, v in _ESS_TEMPLATES.items() if v.get("container")]
        await _hbatch(
            "UPSERT SPARK_ESS_TEMPLATES (key, container, slot) VALUES (?, ?, ?) WITH PRIMARY KEY",
            param_list
        )
    except Exception as e:
        hana_error = str(e)
    if hana_error:
        return {"ok": True, "templates": _ESS_TEMPLATES,
                "warning": f"Salvo em memória mas NÃO persistido: {hana_error}"}
    return {"ok": True, "templates": _ESS_TEMPLATES}

# ── Test send endpoint ─────────────────────────────────────────────────────────
@app.post("/api/registrations/send-test")
async def send_test_email(request: Request, body: Any = Body(...)):
    _check_api_key(request)
    data = body if isinstance(body, dict) else {}
    email_type = data.get("type")
    reg_id = data.get("reg_id")
    if email_type not in ("confirmation", "rejection", "rsvp", "teams_link"):
        raise HTTPException(status_code=400, detail="type must be: confirmation, rejection, rsvp, or teams_link")
    if not reg_id:
        raise HTTPException(status_code=400, detail="reg_id required")
    caller_email = _get_caller_email(request)
    if not caller_email:
        raise HTTPException(status_code=401, detail="Could not determine caller email from token")
    rows = await _hq("SELECT id, data_json FROM SPARK_REGISTRATIONS WHERE id = ?", (reg_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="Registration not found")
    reg = _from_hana(rows[0])
    reg["_id"] = reg_id
    if email_type == "teams_link":
        teams_url = await _teams_url_from_session(
            reg.get("session", ""), reg.get("sessionDate", "") or reg.get("date", ""),
        )
        if teams_url:
            reg["_teamsUrl"] = teams_url
    lang = _lang_from_reg(reg)
    subject, html = _build_email(reg, email_type)
    try:
        container, slot = _get_template(email_type, lang)
        await _ess_send_email(caller_email, "Test", "[TEST] " + subject, html, container, slot)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Test send failed: {exc}")
    return {"ok": True, "sent_to": caller_email}


# ── Batch notify (async) ───────────────────────────────────────────────────────
async def _run_batch_job(job_id: str, ids: list, email_type: str, teams_url: str):
    job = _batch_jobs[job_id]
    for reg_id in ids:
        if job.get("cancel"):
            job["status"] = "cancelled"
            return
        try:
            rows = await _hq("SELECT id, data_json FROM SPARK_REGISTRATIONS WHERE id = ?", (reg_id,))
            if not rows:
                job["results"].append({"id": reg_id, "ok": False, "error": "Not found"})
                job["failed"] += 1
                continue
            reg = _from_hana(rows[0])
            reg["_id"] = reg_id
            effective_url = teams_url
            if email_type == "teams_link" and not effective_url:
                effective_url = await _teams_url_from_session(
                    reg.get("session", ""), reg.get("sessionDate", "") or reg.get("date", ""),
                )
            if effective_url:
                reg["_teamsUrl"] = effective_url
                reg["teamsUrl"] = effective_url
                await _upsert_reg(reg_id, reg)
            elif email_type == "teams_link":
                session_name = reg.get("session", "")
                job["results"].append({"id": reg_id, "ok": False,
                    "error": f"Teams URL não encontrado para '{session_name}'"})
                job["failed"] += 1
                continue
            to_email = reg.get("email", "")
            if not to_email:
                job["results"].append({"id": reg_id, "ok": False, "error": "No email"})
                job["failed"] += 1
                continue
            lang = _lang_from_reg(reg)
            subject, html = _build_email(reg, email_type)
            container, slot = _get_template(email_type, lang)
            to_name = reg.get("name", "")
            await _ess_send_email(to_email, to_name, subject, html, container, slot)
            job["results"].append({"id": reg_id, "ok": True, "to": to_email, "name": to_name})
            job["sent"] += 1
            flag_field = _FLAG_FIELD.get(email_type)
            if flag_field:
                reg[flag_field] = True
                await _upsert_reg(reg_id, reg)
        except Exception as exc:
            job["results"].append({"id": reg_id, "ok": False, "error": str(exc)[:200]})
            job["failed"] += 1
    if job.get("status") == "running":
        job["status"] = "completed"


@app.post("/api/registrations/batch-notify")
async def batch_notify(request: Request, body: Any = Body(...)):
    _check_api_key(request)
    data = body if isinstance(body, dict) else {}
    ids = data.get("ids", [])
    email_type = data.get("type")
    teams_url  = data.get("teamsUrl", "")
    if email_type not in ("confirmation", "rejection", "rsvp", "teams_link"):
        raise HTTPException(status_code=400, detail="type must be: confirmation, rejection, rsvp, or teams_link")
    if not ids:
        raise HTTPException(status_code=400, detail="ids must be a non-empty list")
    job_id = _uuid.uuid4().hex
    _batch_jobs[job_id] = {"status": "running", "total": len(ids), "sent": 0, "failed": 0, "results": [], "cancel": False}
    asyncio.create_task(_run_batch_job(job_id, ids, email_type, teams_url))
    return {"job_id": job_id, "total": len(ids)}


@app.get("/api/batch-jobs/{job_id}")
async def get_batch_job(job_id: str, request: Request):
    _check_api_key(request)
    job = _batch_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@app.post("/api/batch-jobs/{job_id}/cancel")
async def cancel_batch_job(job_id: str, request: Request):
    _check_api_key(request)
    job = _batch_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    job["cancel"] = True
    return {"ok": True}


# ── Auth endpoints ─────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    email: str
    password: str

class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str

@app.post("/api/auth/register", status_code=201)
async def auth_register(body: RegisterRequest):
    email = body.email.strip().lower()
    rows = await _hq("SELECT id FROM SPARK_USERS WHERE email = ?", (email,))
    if rows:
        raise HTTPException(status_code=409, detail="Email already registered.")
    user_id = _uuid.uuid4().hex
    data = {"id": user_id, "email": email, "name": body.name.strip(),
            "password_hash": _hash_pw(body.password), "approved": True,
            "role": "user", "modules": [],
            "created_at": datetime.now(timezone.utc).isoformat()}
    await _upsert_user(user_id, data)
    return {"ok": True, "message": "Registration complete. You can now log in."}

@app.post("/api/auth/login")
async def auth_login(body: LoginRequest):
    email = body.email.strip().lower()
    rows = await _hq("SELECT id, data_json FROM SPARK_USERS WHERE email = ?", (email,))
    if not rows:
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    user = _from_hana(rows[0])
    if not _check_pw(body.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.get("approved", True):
        raise HTTPException(status_code=403, detail="Account pending approval.")
    role = user.get("role", "user")
    if user["email"].lower() == _ADMIN_EMAIL:
        role = "admin"
    modules = user.get("modules", [])
    token = _make_token(user["id"], user["email"], user.get("name", ""), role)
    return {"ok": True, "name": user.get("name", ""), "email": user["email"],
            "token": token, "role": role, "modules": modules, "expires_in": _JWT_EXPIRY}

# ── User management (admin) ────────────────────────────────────────────────────
@app.get("/api/users")
async def list_users(request: Request):
    _check_admin(request)
    rows = await _hq("SELECT id, data_json FROM SPARK_USERS LIMIT 1000", ())
    users = [_from_hana(r) for r in rows]
    return [{k: v for k, v in u.items() if k != "password_hash"} for u in users]

class ApproveRequest(BaseModel):
    approved: bool = True

@app.patch("/api/users/{user_id}/approve")
async def approve_user(user_id: str, body: ApproveRequest, request: Request):
    _check_admin(request)
    rows = await _hq("SELECT id, data_json FROM SPARK_USERS WHERE id = ?", (user_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="User not found")
    user = _from_hana(rows[0])
    user["approved"] = body.approved
    await _upsert_user(user_id, user)
    return {"ok": True, "approved": body.approved}

@app.patch("/api/users/{user_id}/password")
async def reset_user_password(user_id: str, request: Request, body: Any = Body(...)):
    _check_admin(request)
    password = (body or {}).get("password", "") if isinstance(body, dict) else ""
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters.")
    rows = await _hq("SELECT id, data_json FROM SPARK_USERS WHERE id = ?", (user_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="User not found")
    user = _from_hana(rows[0])
    user["password_hash"] = _hash_pw(password)
    await _upsert_user(user_id, user)
    return {"ok": True}

@app.post("/api/users", status_code=201)
async def create_user(request: Request, body: Any = Body(...)):
    _check_admin(request)
    data = body if isinstance(body, dict) else {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    name = data.get("name", "").strip()
    if not email or not password or not name:
        raise HTTPException(status_code=400, detail="email, password, and name are required.")
    rows = await _hq("SELECT id FROM SPARK_USERS WHERE email = ?", (email,))
    if rows:
        raise HTTPException(status_code=409, detail="Email already registered.")
    user_id = _uuid.uuid4().hex
    user_data = {"id": user_id, "email": email, "name": name,
                 "password_hash": _hash_pw(password), "approved": True,
                 "role": "user", "modules": [],
                 "created_at": datetime.now(timezone.utc).isoformat()}
    await _upsert_user(user_id, user_data)
    return {"ok": True}

@app.delete("/api/users/{user_id}", status_code=204)
async def delete_user(user_id: str, request: Request):
    _check_admin(request)
    await _hx("DELETE FROM SPARK_USERS WHERE id = ?", (user_id,))

class RoleRequest(BaseModel):
    role: str

@app.patch("/api/users/{user_id}/role")
async def set_user_role(user_id: str, body: RoleRequest, request: Request):
    _check_super_admin(request)
    if body.role not in ("user", "co-admin"):
        raise HTTPException(status_code=400, detail="Role must be 'user' or 'co-admin'.")
    rows = await _hq("SELECT id, data_json FROM SPARK_USERS WHERE id = ?", (user_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="User not found")
    user = _from_hana(rows[0])
    user["role"] = body.role
    await _upsert_user(user_id, user)
    return {"ok": True, "role": body.role}

_VALID_MODULES = {"sessions", "calendar", "analytics", "activity", "registrations", "reports", "intelligence", "campaigns", "leads"}

class ModulesRequest(BaseModel):
    modules: list[str]

@app.patch("/api/users/{user_id}/modules")
async def set_user_modules(user_id: str, body: ModulesRequest, request: Request):
    _check_super_admin(request)
    modules = [m for m in body.modules if m in _VALID_MODULES]
    rows = await _hq("SELECT id, data_json FROM SPARK_USERS WHERE id = ?", (user_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="User not found")
    user = _from_hana(rows[0])
    user["modules"] = modules
    await _upsert_user(user_id, user)
    return {"ok": True, "modules": modules}


class UserEditRequest(BaseModel):
    role: str | None = None
    modules: list[str] | None = None
    approved: bool | None = None

@app.patch("/api/users/{user_id}")
async def update_user(user_id: str, body: UserEditRequest, request: Request):
    _check_super_admin(request)
    rows = await _hq("SELECT id, data_json FROM SPARK_USERS WHERE id = ?", (user_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="User not found")
    user = _from_hana(rows[0])
    if body.role is not None:
        if body.role not in ("user", "co-admin"):
            raise HTTPException(status_code=400, detail="Role must be 'user' or 'co-admin'.")
        user["role"] = body.role
    if body.modules is not None:
        user["modules"] = [m for m in body.modules if m in _VALID_MODULES]
    if body.approved is not None:
        user["approved"] = body.approved
    await _upsert_user(user_id, user)
    return {"ok": True}


# ── Analytics data persistence ────────────────────────────────────────────────

async def _ana_upsert(table: str, docs: list, id_field: str) -> int:
    ts = datetime.now(timezone.utc).isoformat()
    param_list = []
    for doc in docs:
        doc_id = str(doc.get(id_field) or "").strip().replace("/", "_").replace(" ", "_")
        if not doc_id:
            continue
        param_list.append((doc_id, json.dumps(doc), ts))
    if not param_list:
        return 0
    return await _hbatch(
        f"UPSERT {table} (id, data_json, uploaded_at) VALUES (?, ?, ?) WITH PRIMARY KEY",
        param_list
    )

@app.post("/api/analytics/campaigns/upload")
async def upload_analytics_campaigns(request: Request, body: Any = Body(...)):
    _check_api_key(request)
    docs = body if isinstance(body, list) else []
    written = await _ana_upsert("SPARK_ANALYTICS_CAMPAIGNS", docs, "crmId")
    return {"ok": True, "written": written}

@app.post("/api/analytics/registrations/upload")
async def upload_analytics_registrations(request: Request, body: Any = Body(...)):
    _check_api_key(request)
    docs = body if isinstance(body, list) else []
    written = await _ana_upsert("SPARK_ANALYTICS_REGISTRATIONS", docs, "regId")
    return {"ok": True, "written": written}

@app.get("/api/analytics/campaigns")
async def get_analytics_campaigns(request: Request):
    _check_api_key(request)
    rows = await _hq("SELECT data_json FROM SPARK_ANALYTICS_CAMPAIGNS LIMIT 10000", ())
    return [json.loads(r["data_json"]) for r in rows]

@app.get("/api/analytics/registrations")
async def get_analytics_registrations(request: Request):
    _check_api_key(request)
    rows = await _hq("SELECT data_json FROM SPARK_ANALYTICS_REGISTRATIONS LIMIT 10000", ())
    return [json.loads(r["data_json"]) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# ── DH App Portal integration ─────────────────────────────────────────────────

_DH_API_URL    = os.environ.get("DH_API_URL", "https://dh-api.cfapps.us10-002.hana.ondemand.com")
_DH_JWT_SECRET = os.environ.get("DH_JWT_SECRET", "")

# Spark Meeting area → DH App Pipeline solution_area_l1
_SPARK_TO_L1: dict[str, list[str]] = {
    "HCM":            ["Human Capital Management"],
    "HCM + Finance":  ["Human Capital Management", "Finance and Spend Management"],
    "Finance":        ["Finance and Spend Management"],
    "Procurement":    ["Finance and Spend Management"],
    "CX":             ["Customer Experience"],
    "BTP":            ["BAIP - Data & AI", "BAIP - Technology Foundation", "Business Technology Platform"],
    "SCM":            ["Supply Chain Management"],
    "Supply Chain":   ["Supply Chain Management"],
    "Business Suite": ["Cloud ERP Private", "Cloud ERP Public"],
    "Data & AI":      ["BAIP - Data & AI"],
}

_PERSONAL = {"gmail.com", "hotmail.com", "yahoo.com", "outlook.com",
             "yahoo.com.br", "hotmail.com.br", "gmail.com.br", "uol.com.br"}


def _dh_bearer() -> str:
    if not _DH_JWT_SECRET:
        raise HTTPException(status_code=503, detail="DH_JWT_SECRET not configured")
    now = datetime.now(timezone.utc)
    token = pyjwt.encode(
        {"sub": "spark-service@sap.com", "name": "Spark Meeting", "role": "viewer",
         "modules": [], "iat": now, "exp": now + timedelta(minutes=30)},
        _DH_JWT_SECRET, algorithm="HS256",
    )
    return token


# ── Registration Import ────────────────────────────────────────────────────────

_IMPORT_SKIP_STATUSES = {"cancelled", "declined", "rejected", "cancellation requested"}
_IMPORT_FILENAME_RE   = re.compile(r"^(.+)-(\d{2})_(\d{2})\.xlsx$", re.IGNORECASE)


def _parse_import_filename(filename: str) -> tuple[str, str]:
    """Return (session_title, session_date_YYYY-MM-DD) or raise HTTPException."""
    m = _IMPORT_FILENAME_RE.match(filename)
    if not m:
        raise HTTPException(
            status_code=400,
            detail=f"Filename must match 'Session Name-DD_MM.xlsx', got: {filename}",
        )
    session_title = m.group(1).strip()
    day, month = int(m.group(2)), int(m.group(3))
    now = datetime.now(timezone.utc)
    year = now.year if month >= now.month else now.year + 1
    try:
        date_str = datetime(year, month, day).strftime("%Y-%m-%d")
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid date {day}/{month} in filename")
    return session_title, date_str


@app.post("/api/registrations/import")
async def import_registrations(
    request: Request,
    file: UploadFile = File(...),
    session_title: str = Form(None),
    session_date: str = Form(None),
    source: str = Form(None),
    source_id: str = Form(None),
):
    _check_api_key(request)
    # Resolve source name from source_id if provided
    if source_id:
        rows = await _hq("SELECT name FROM SPARK_LIST_SOURCES WHERE id = ?", (source_id,))
        if rows:
            source = rows[0]["name"]
    try:
        import openpyxl
    except ImportError:
        raise HTTPException(status_code=500, detail="openpyxl not installed")

    # Use explicit params when provided; fall back to filename parsing
    if session_title and session_date:
        title, date = session_title.strip(), session_date.strip()
    else:
        title, date = _parse_import_filename(file.filename or "")

    contents = await file.read()
    import io
    wb = openpyxl.load_workbook(io.BytesIO(contents), read_only=True, data_only=True)
    ws = wb.active

    rows = list(ws.iter_rows(values_only=True))
    if len(rows) < 2:
        raise HTTPException(status_code=400, detail="Excel file has fewer than 2 rows")

    # Row 0 = "Registration Report" banner; row 1 = headers
    headers = [str(h).strip() if h is not None else "" for h in rows[1]]
    col = {name: idx for idx, name in enumerate(headers)}

    def _get(row, key: str, default="") -> str:
        idx = col.get(key)
        if idx is None:
            return default
        v = row[idx]
        return str(v).strip() if v is not None else default

    now_ts = datetime.now(timezone.utc).isoformat()
    imported = 0
    skipped = 0
    duplicate = 0
    errors = 0
    logs = []

    for row_idx, row in enumerate(rows[2:], start=3):
        reg_status = _get(row, "Registration Status").lower()
        if reg_status in _IMPORT_SKIP_STATUSES:
            skipped += 1
            logs.append({"row": row_idx, "email": _get(row, "Email Address"), "name": "", "status": "skipped", "detail": f"Status: {reg_status}"})
            continue

        email = _get(row, "Email Address").lower()
        if not email:
            skipped += 1
            logs.append({"row": row_idx, "email": "", "name": "", "status": "skipped", "detail": "No email address"})
            continue

        first = _get(row, "First Name")
        last  = _get(row, "Last Name")
        name  = f"{first} {last}".strip() or email

        slug = hashlib.sha1(f"{email}_{title}".encode()).hexdigest()[:20]

        reg_date_raw = _get(row, "Registration Date Time")
        registered_at = reg_date_raw if reg_date_raw else now_ts

        attended_raw = _get(row, "Attended").lower()
        attended = attended_raw == "yes"

        contact_raw = _get(row, "Ser-contactado-futuro").lower().strip()
        sap_contact = contact_raw in ("si", "sí", "yes", "sim", "s", "true", "1")

        data = {
            "email":        email,
            "name":         name,
            "organization": _get(row, "Company"),
            "role":         _get(row, "Function"),
            "country":      _get(row, "Country"),
            "session":      title,
            "sessionDate":  date,
            "attended":     attended,
            "sapContact":   sap_contact,
            "source":       (source or "import").strip(),
            "registeredAt": registered_at,
        }
        existing = await _hq("SELECT id FROM SPARK_REGISTRATIONS WHERE id = ?", (slug,))
        is_duplicate = bool(existing)
        data["id"] = slug
        await _upsert_reg(slug, data)
        if is_duplicate:
            duplicate += 1
            logs.append({"row": row_idx, "email": email, "name": name, "status": "updated", "detail": "Existing record updated"})
        else:
            imported += 1
            logs.append({"row": row_idx, "email": email, "name": name, "status": "imported", "detail": ""})

    return {"ok": True, "imported": imported, "skipped": skipped, "duplicate": duplicate, "errors": errors, "logs": logs}


def _norm_name(name: str) -> str:
    """Normalize a name for fuzzy matching: lowercase, strip accents, collapse spaces."""
    nfkd = unicodedata.normalize("NFKD", name or "")
    ascii_str = "".join(c for c in nfkd if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", ascii_str.lower().strip())


def _name_similarity(a: str, b: str) -> float:
    """Returns 0-1 similarity between two already-normalized names."""
    from difflib import SequenceMatcher
    if not a or not b:
        return 0.0
    seq = SequenceMatcher(None, a, b).ratio()
    a_tok, b_tok = set(a.split()), set(b.split())
    jaccard = len(a_tok & b_tok) / len(a_tok | b_tok) if (a_tok or b_tok) else 0.0
    return max(seq, jaccard)


@app.post("/api/registrations/attendance")
async def import_attendance(
    request: Request,
    file: UploadFile = File(...),
    session_title: str = Form(...),
):
    _check_api_key(request)
    content = await file.read()

    # Parse Excel — look for a Name column or fall back to first column
    import openpyxl, io
    wb = openpyxl.load_workbook(io.BytesIO(content), read_only=True, data_only=True)
    ws = wb.active
    rows = list(ws.iter_rows(values_only=True))
    wb.close()

    if not rows:
        raise HTTPException(status_code=400, detail="Empty file")

    header = [str(c).strip().lower() if c else "" for c in rows[0]]

    # Detect Teams attendance format: "Nome / E-mail" + "Status" columns (Portuguese export)
    nome_col   = next((i for i, h in enumerate(header) if "nome" in h and "e-mail" in h), None)
    status_col = next((i for i, h in enumerate(header) if h == "status"), None)
    is_teams   = nome_col is not None and status_col is not None

    attended_names:  list[str] = []
    attended_emails: list[str] = []

    if is_teams:
        _ACCEPTED = {"aceito", "organizador"}
        for row in rows[1:]:
            val    = str(row[nome_col]   or "").strip()
            status = str(row[status_col] or "").strip().lower()
            if not val or status not in _ACCEPTED:
                continue
            if "@" in val:
                attended_emails.append(val.lower())
            else:
                # "Lastname, Firstname" → "Firstname Lastname"
                if "," in val:
                    parts = val.split(",", 1)
                    val = parts[1].strip() + " " + parts[0].strip()
                attended_names.append(val)
    else:
        name_col  = next((i for i, h in enumerate(header) if "name" in h), None)
        first_col = next((i for i, h in enumerate(header) if "first" in h), None)
        last_col  = next((i for i, h in enumerate(header) if "last"  in h), None)
        data_start = 1
        if name_col is None and first_col is None:
            name_col = 0
            data_start = 0
        for row in rows[data_start:]:
            if first_col is not None and last_col is not None:
                first = str(row[first_col] or "").strip()
                last  = str(row[last_col]  or "").strip()
                full  = f"{first} {last}".strip()
            elif name_col is not None:
                full = str(row[name_col] or "").strip()
            else:
                continue
            if full:
                attended_names.append(full)

    if not attended_names and not attended_emails:
        raise HTTPException(status_code=400, detail="No attendees found in file")

    norm_attended = {_norm_name(n): n for n in attended_names}

    # Fetch all registrations for this session
    all_rows = await _hq("SELECT id, data_json FROM SPARK_REGISTRATIONS LIMIT 10000", ())
    all_regs = [_from_hana(r) for r in all_rows]
    session_regs = [reg for reg in all_regs if reg.get("session") == session_title]

    if not session_regs:
        raise HTTPException(status_code=404, detail=f"No registrations found for session: {session_title}")

    matched = unmatched = errors = 0
    logs: list[dict] = []

    matched_emails_from_regs: set[str] = set()

    for reg in session_regs:
        reg_name  = reg.get("name", "")
        reg_email = reg.get("email", "").lower()
        reg_norm  = _norm_name(reg_name)
        doc_id    = reg.get("id", "")

        email_hit = bool(reg_email and reg_email in attended_emails)
        name_hit  = (
            reg_norm in norm_attended
            or any(reg_norm in nk or nk in reg_norm for nk in norm_attended)
        )
        hit = email_hit or name_hit

        if hit:
            match_how = "email" if email_hit else "name"
            reg["attended"] = True
            await _upsert_reg(doc_id, reg)
            matched += 1
            if email_hit:
                matched_emails_from_regs.add(reg_email)
            logs.append({"name": reg_name, "status": "matched", "detail": match_how})
        else:
            unmatched += 1
            logs.append({"name": reg_name, "status": "unmatched"})

    # Report entries from the file that found no match + compute suggestions
    matched_norms = {_norm_name(l["name"]) for l in logs if l["status"] == "matched"}
    unmatched_excel_emails = [e for e in attended_emails if e not in matched_emails_from_regs]
    excel_unmatched_raw = [n for nk, n in norm_attended.items() if nk not in matched_norms and not any(nk in mk or mk in nk for mk in matched_norms)]

    # For each unmatched reg, compute similarity suggestions from the Excel names
    for entry in logs:
        if entry["status"] == "unmatched":
            reg_norm = _norm_name(entry["name"])
            candidates = []
            for nk, orig_excel in norm_attended.items():
                score = _name_similarity(reg_norm, nk)
                if score >= 0.4:
                    candidates.append({"excel_name": orig_excel, "score": round(score, 2)})
            candidates.sort(key=lambda x: x["score"], reverse=True)
            entry["suggestions"] = candidates[:3]

    # For each Excel name that didn't match, compute suggestions from unmatched regs
    unmatched_regs = [l for l in logs if l["status"] == "unmatched"]
    excel_unmatched = []
    for excel_name in excel_unmatched_raw:
        en = _norm_name(excel_name)
        candidates = []
        for reg in unmatched_regs:
            score = _name_similarity(en, _norm_name(reg["name"]))
            if score >= 0.4:
                reg_id = next((r.get("id", "") for r in session_regs if r.get("name", "") == reg["name"]), "")
                candidates.append({"reg_name": reg["name"], "reg_id": reg_id, "score": round(score, 2)})
        candidates.sort(key=lambda x: x["score"], reverse=True)
        excel_unmatched.append({"excel_name": excel_name, "suggestions": candidates[:3]})

    # Emails from file that had no matching registration
    for email in unmatched_excel_emails:
        excel_unmatched.append({"excel_name": email, "suggestions": []})

    return {
        "ok": True,
        "total_in_file": len(attended_names) + len(attended_emails),
        "matched": matched,
        "unmatched_registrations": unmatched,
        "excel_unmatched": excel_unmatched,
        "errors": errors,
        "logs": logs,
    }


# ── Attendance confirm suggested matches ──────────────────────────────────────

class AttendanceConfirmBody(BaseModel):
    registration_ids: list[str]

@app.post("/api/registrations/attendance/confirm")
async def confirm_attendance(request: Request, body: AttendanceConfirmBody):
    _check_api_key(request)
    confirmed = 0
    errors = []
    for doc_id in body.registration_ids:
        rows = await _hq("SELECT id, data_json FROM SPARK_REGISTRATIONS WHERE id = ?", (doc_id,))
        if rows:
            reg = _from_hana(rows[0])
            reg["attended"] = True
            await _upsert_reg(doc_id, reg)
            confirmed += 1
        else:
            errors.append({"id": doc_id, "status": 404})
    return {"ok": True, "confirmed": confirmed, "errors": errors}


# ── Lead Intelligence ──────────────────────────────────────────────────────────

async def _dh_get(c: httpx.AsyncClient, path: str, params: dict | None = None) -> dict | list | None:
    """Call DH App API with service JWT. Returns parsed JSON or None on error."""
    try:
        r = await c.get(
            f"{_DH_API_URL}{path}",
            headers={"Authorization": f"Bearer {_dh_bearer()}"},
            params=params or {},
            timeout=8,
        )
        if r.is_success:
            return r.json()
    except Exception:
        pass
    return None


async def _classify_org(
    c: httpx.AsyncClient, org: str, l1_areas: list[str],
    account_bpid: str | None = None,
    email_domains: list[str] | None = None,
) -> dict:
    """Return classification + enrichment data for one organization.

    account_bpid: if already resolved (e.g. via domain lookup), skip Outreach name search.
    email_domains: list of domains from participant emails — used to resolve account_bpid
                   when it is not provided, as a more reliable alternative to name search.
    """
    account_bp = account_bpid or None
    contacts: list[dict] = []
    bp_data: dict | None = None  # populated when pipeline/account/{bp} is called

    # 1a. If account_bpid already known, fetch contacts directly by BP
    if account_bp:
        contacts_data = await _dh_get(c, f"/api/outreach/contacts/{account_bp}")
        raw = contacts_data.get("contacts", []) if isinstance(contacts_data, dict) else []
        contacts = raw if isinstance(raw, list) else []

    # 1b. If BP not known, try domain lookup before falling back to name search
    if not account_bp and email_domains:
        for domain in email_domains:
            domain_data = await _dh_get(c, f"/api/outreach/contacts/by-domain/{domain}")
            if isinstance(domain_data, dict) and domain_data.get("match"):
                account_bp = str(domain_data["match"]["account_bpid"])
                contacts_data = await _dh_get(c, f"/api/outreach/contacts/{account_bp}")
                raw = contacts_data.get("contacts", []) if isinstance(contacts_data, dict) else []
                contacts = raw if isinstance(raw, list) else []
                break

    # 1c. Final fallback: fuzzy name search in Outreach
    if not account_bp:
        contacts_data = await _dh_get(c, f"/api/outreach/contacts/search/{org}")
        raw = contacts_data.get("contacts", []) if isinstance(contacts_data, dict) else (contacts_data if isinstance(contacts_data, list) else [])
        contacts = raw if isinstance(raw, list) else []
        for contact in contacts:
            bp = contact.get("account_bpid") or contact.get("account_bp")
            if bp:
                account_bp = str(bp)
                break

    # 2. Installed base (adoption check)
    installed_solutions: list[str] = []
    installed_products: list[str] = []
    installed_by_l1: dict[str, list[str]] = {}
    adopted = False
    if account_bp:
        ib_data = await _dh_get(c, f"/api/ae-analysis/installed-base/{account_bp}")
        if ib_data and isinstance(ib_data, dict):
            solutions_dict = ib_data.get("solutions", {})
            for sol_l1, products in solutions_dict.items():
                live = [p.get("product_label", sol_l1) for p in (products if isinstance(products, list) else []) if p.get("status", "").lower() == "live"]
                if live:
                    installed_solutions.append(sol_l1)
                    installed_products.extend(live)
                    installed_by_l1[sol_l1] = live
            if l1_areas and any(s in l1_areas for s in installed_solutions):
                adopted = True

    # 3. Pipeline opps — query by account_bp directly if known, otherwise by name
    open_opps = 0
    pipeline_summary: list[dict] = []
    ae_list: list[str] = []
    region_list: list[str] = []

    if account_bp:
        # Direct account_bp lookup — precise, no name-matching ambiguity
        bp_data = await _dh_get(c, f"/api/pipeline/account/{account_bp}")
        if bp_data and isinstance(bp_data, dict):
            open_opps = bp_data.get("open_opps", 0)
            for opp in (bp_data.get("opportunities") or []):
                drm = (opp.get("drm_category") or "").lower()
                if drm in ("disc/lost", "booked/won", "excluded from pipeline"):
                    continue
                ae_name  = opp.get("opp_owner_name", "")
                ae_email = opp.get("opp_owner_email", "")
                flsm     = opp.get("flsm", "")
                region   = opp.get("region_lvl2") or opp.get("region_lvl3") or opp.get("region_lvl4", "")
                # Only include opps matching the session's L1 area (if filter active)
                sol_l1 = opp.get("solution_area_l1", "")
                if l1_areas and sol_l1 not in l1_areas:
                    continue
                pipeline_summary.append({
                    "id":          opp.get("opportunity_id", ""),
                    "phase":       opp.get("opp_phase", ""),
                    "acv":         opp.get("acv_usd"),
                    "qtr":         opp.get("closing_qtr", ""),
                    "ae":          ae_name,
                    "ae_email":    ae_email,
                    "flsm":        flsm,
                    "region":      region,
                    "solution_l1": sol_l1,
                    "solution_l2": opp.get("sub_solution_area_l2", ""),
                })
                if ae_name and ae_name not in ae_list:
                    ae_list.append(ae_name)
                if region and region not in region_list:
                    region_list.append(region)
            # If no L1 filter matched, fall back to all open opps for AE/FLSM/region
            if not pipeline_summary:
                ae_list   = [x for x in [bp_data.get("ae")] if x]
                region_list = [x for x in [bp_data.get("region")] if x]
    elif l1_areas:
        # Fallback: name-based search (less reliable)
        for l1 in l1_areas[:1]:
            pipeline_data = await _dh_get(c, "/api/pipeline", {
                "search": org,
                "sol_l1": l1,
                "limit": 10,
            })
            if pipeline_data and isinstance(pipeline_data, list):
                for opp in pipeline_data:
                    phase = (opp.get("opp_phase") or "").lower()
                    if phase not in ("closed - won", "closed - lost", "lost", "won"):
                        open_opps += 1
                        ae_name  = opp.get("opp_owner_name") or opp.get("ae_name", "")
                        ae_email = opp.get("opp_owner_email") or opp.get("ae_email", "")
                        flsm     = opp.get("FLSM") or opp.get("flsm", "")
                        region   = opp.get("region_lvl2") or opp.get("region_lvl3") or opp.get("region_lvl4", "")
                        pipeline_summary.append({
                            "id":          opp.get("opportunity_id", ""),
                            "phase":       opp.get("opp_phase", ""),
                            "acv":         opp.get("acv_usd") or opp.get("acv_total_opp"),
                            "qtr":         opp.get("closing_qtr", ""),
                            "ae":          ae_name,
                            "ae_email":    ae_email,
                            "flsm":        flsm,
                            "region":      region,
                            "solution_l1": opp.get("solution_area_l1", ""),
                            "solution_l2": opp.get("sub_solution_area_l2", ""),
                        })
                        if ae_name and ae_name not in ae_list:
                            ae_list.append(ae_name)
                        if region and region not in region_list:
                            region_list.append(region)

    # 4. Classification
    if adopted:
        classification = "adoption"
    elif open_opps > 0 or pipeline_summary:
        classification = "maturation"
    else:
        classification = "potential_lead"

    # Top 3 contacts by engaged_score
    top_contacts = sorted(
        [{"name":  f"{c_.get('first_name','')} {c_.get('last_name','')}".strip(),
          "title": c_.get("title", ""),
          "email": c_.get("email", ""),
          "score": c_.get("engaged_score") or 0}
         for c_ in contacts],
        key=lambda x: x["score"],
        reverse=True,
    )[:3]

    # Collect FLSM and ae_email from pipeline
    flsm_list: list[str] = []
    ae_email_list: list[str] = []
    for opp in pipeline_summary:
        if opp.get("flsm") and opp["flsm"] not in flsm_list:
            flsm_list.append(opp["flsm"])
        if opp.get("ae_email") and opp["ae_email"] not in ae_email_list:
            ae_email_list.append(opp["ae_email"])

    if account_bp and not pipeline_summary and bp_data:
        if bp_data.get("flsm") and bp_data["flsm"] not in flsm_list:
            flsm_list.append(bp_data["flsm"])
        for extra_ae in ([bp_data.get("ae")] + (bp_data.get("aes") or [])):
            if extra_ae and extra_ae not in ae_list:
                ae_list.append(extra_ae)
        for extra_flsm in bp_data.get("flsms") or []:
            if extra_flsm and extra_flsm not in flsm_list:
                flsm_list.append(extra_flsm)

    return {
        "classification":      classification,
        "open_opps":           open_opps,
        "pipeline":            pipeline_summary,
        "installed_solutions": list(set(installed_solutions)),
        "installed_products":  list(dict.fromkeys(installed_products)),
        "installed_by_l1":     installed_by_l1,
        "top_contacts":        top_contacts,
        "account_bp":          account_bp,
        "ae":                  ae_list[0] if ae_list else None,
        "ae_email":            ae_email_list[0] if ae_email_list else None,
        "flsm":                flsm_list[0] if flsm_list else None,
        "region":              region_list[0] if region_list else None,
        "aes":                 ae_list,
        "ae_emails":           ae_email_list,
        "flsms":               flsm_list,
        "regions":             region_list,
    }


@app.get("/api/intelligence")
async def get_intelligence(request: Request, session: list[str] = Query(default=[])):
    _check_api_key(request)

    if not session:
        raise HTTPException(status_code=400, detail="At least one session is required")

    session_set = set(session)

    # Fetch all registrations and filter for selected sessions
    all_rows = await _hq("SELECT id, data_json FROM SPARK_REGISTRATIONS LIMIT 10000", ())
    all_regs = [_from_hana(r) for r in all_rows]
    session_regs = [reg for reg in all_regs if reg.get("session") in session_set]

    if not session_regs:
        return {"sessions": list(session), "companies": [], "total": 0, "summary": {"potential_lead": 0, "maturation": 0, "adoption": 0}}

    # Find area for each selected session → union of all L1 areas
    l1_areas_set: set[str] = set()
    session_areas: list[str] = []
    sess_rows = await _hq("SELECT id, data_json FROM SPARK_SESSIONS LIMIT 500", ())
    for row in sess_rows:
        s = _from_hana(row)
        if s.get("title") in session_set:
            area = s.get("area", "")
            if area:
                session_areas.append(area)
                l1_areas_set.update(_SPARK_TO_L1.get(area, []))

    l1_areas = list(l1_areas_set)

    # ── Pre-resolve email domains → canonical account_bpid + account_name ────────
    # Collect all email domains per org group, then resolve domains in bulk
    # so inconsistent org names ("Jan/SA", "Implementos agricos Jan", etc.)
    # all map to the same canonical account_bpid from Outreach.

    # Step A: group participants by their raw org label, collect domains
    raw_orgs: dict[str, list] = {}
    org_domains: dict[str, set] = {}  # raw_org → set of email domains
    for reg in session_regs:
        org = (reg.get("organization") or reg.get("org") or "Unknown").strip()
        raw_orgs.setdefault(org, []).append({
            "name":         reg.get("name", ""),
            "email":        reg.get("email", ""),
            "country":      reg.get("country", ""),
            "role":         reg.get("role") or reg.get("function", ""),
            "attended":     reg.get("attended", False),
            "session":      reg.get("session", ""),
            "session_date": reg.get("sessionDate") or reg.get("session_date", ""),
            "sapContact":   reg.get("sapContact"),
        })
        email = (reg.get("email") or "").strip().lower()
        if "@" in email:
            domain = email.split("@", 1)[1]
            if domain and domain not in _PERSONAL:
                org_domains.setdefault(org, set()).add(domain)

    # Step B: resolve all unique domains (bounded concurrency: 5 at a time)
    all_domains = {d for ds in org_domains.values() for d in ds}
    domain_cache: dict[str, dict | None] = {}
    _sem_domain = asyncio.Semaphore(5)

    async def _resolve_domain(domain: str):
        async with _sem_domain:
            async with httpx.AsyncClient(timeout=10) as hc:
                result = await _dh_get(hc, f"/api/outreach/contacts/by-domain/{domain}")
                if isinstance(result, dict) and result.get("match"):
                    domain_cache[domain] = result["match"]
                else:
                    domain_cache[domain] = None

    await asyncio.gather(*[_resolve_domain(d) for d in all_domains])

    # Step C: for each raw_org, pick the best account_bpid + canonical name
    # by choosing the domain match with the most pipeline_opps
    org_bp_map: dict[str, str | None] = {}     # raw_org → account_bpid
    org_canon_map: dict[str, str] = {}          # raw_org → canonical account_name
    for org, domains in org_domains.items():
        best_match = None
        for d in domains:
            match = domain_cache.get(d)
            if match:
                if best_match is None or (match.get("pipeline_opps", 0) > best_match.get("pipeline_opps", 0)):
                    best_match = match
        if best_match:
            org_bp_map[org] = str(best_match["account_bpid"])
            org_canon_map[org] = best_match["account_name"] or org
        else:
            org_bp_map[org] = None
            org_canon_map[org] = org

    # Step D: merge raw_org groups that resolve to the same account_bpid
    # (e.g. "Jan/SA" and "Implementos agricos Jan" → "Implementos Agricolas Jan S/A")
    orgs: dict[str, list] = {}           # canonical_name → participants
    orgs_bp: dict[str, str | None] = {}  # canonical_name → account_bpid
    orgs_domains: dict[str, list] = {}   # canonical_name → domains list
    seen_bps: dict[str, str] = {}        # account_bpid → canonical_name already used

    for raw_org, participants in raw_orgs.items():
        bp   = org_bp_map.get(raw_org)
        canon = org_canon_map.get(raw_org, raw_org)
        if bp and bp in seen_bps:
            # Merge into the existing canonical group
            key = seen_bps[bp]
        else:
            key = canon
            if bp:
                seen_bps[bp] = key
        orgs.setdefault(key, []).extend(participants)
        if bp:
            orgs_bp[key] = bp
        orgs_domains.setdefault(key, [])
        for d in org_domains.get(raw_org, set()):
            if d not in orgs_domains[key]:
                orgs_domains[key].append(d)

    # Classify each org (max 10 concurrent)
    semaphore = asyncio.Semaphore(10)

    async def _classify_with_sem(org: str):
        async with semaphore:
            async with httpx.AsyncClient(timeout=15) as c:
                try:
                    result = await _classify_org(
                        c, org, l1_areas,
                        account_bpid=orgs_bp.get(org),
                        email_domains=orgs_domains.get(org, []),
                    )
                except Exception:
                    result = {"classification": "unknown", "open_opps": 0, "pipeline": [],
                              "installed_solutions": [], "installed_products": [], "installed_by_l1": {},
                              "top_contacts": [], "account_bp": None,
                              "ae": None, "ae_email": None, "flsm": None, "region": None,
                              "aes": [], "ae_emails": [], "flsms": [], "regions": []}
                return {"organization": org, "participants": orgs[org], **result}

    tasks = [_classify_with_sem(org) for org in orgs]
    companies = await asyncio.gather(*tasks)

    order = {"potential_lead": 0, "maturation": 1, "adoption": 2, "unknown": 3}
    companies = sorted(companies, key=lambda x: order.get(x.get("classification", "unknown"), 3))

    # Persist results to HANA so they appear in the snapshot picker
    try:
        slug = re.sub(r"[^a-z0-9]+", "-", "_".join(sorted(session_set)).lower())[:80]
        area_label = session_areas[0] if len(session_areas) == 1 else ", ".join(sorted(set(session_areas)))
        sess_label = list(session_set)[0] if len(session_set) == 1 else json.dumps(sorted(session_set))
        snap_data = {
            "id":          slug,
            "session":     sess_label,
            "sessionArea": area_label,
            "analyzedAt":  datetime.now(timezone.utc).isoformat(),
            "companies":   json.dumps(list(companies)),
            "summary":     json.dumps({
                "potential_lead": sum(1 for co in companies if co.get("classification") == "potential_lead"),
                "maturation":     sum(1 for co in companies if co.get("classification") == "maturation"),
                "adoption":       sum(1 for co in companies if co.get("classification") == "adoption"),
                "total":          len(session_regs),
            }),
        }
        await _hx(
            "UPSERT SPARK_INTELLIGENCE_SNAPSHOTS (id, session, session_area, analyzed_at, data_json) "
            "VALUES (?, ?, ?, ?, ?) WITH PRIMARY KEY",
            (slug, sess_label[:4000], area_label[:256], snap_data["analyzedAt"], json.dumps(snap_data))
        )
    except Exception as _pe:
        pass  # persistence failure must not block the live response

    return {
        "sessions":      list(session),
        "session_areas": list(set(session_areas)),
        "l1_areas":      l1_areas,
        "total":         len(session_regs),
        "companies":     list(companies),
        "summary": {
            "potential_lead": sum(1 for co in companies if co.get("classification") == "potential_lead"),
            "maturation":     sum(1 for co in companies if co.get("classification") == "maturation"),
            "adoption":       sum(1 for co in companies if co.get("classification") == "adoption"),
        },
    }


# ── Intelligence: batch run (called by LaunchAgent 2x/day) ───────────────────

@app.post("/api/intelligence/run-batch")
async def run_intelligence_batch(request: Request):
    _check_api_key(request)

    # Load all sessions
    sess_rows = await _hq("SELECT id, data_json FROM SPARK_SESSIONS LIMIT 500", ())
    sessions_docs = [_from_hana(r) for r in sess_rows]

    # Load all registrations once
    all_rows = await _hq("SELECT id, data_json FROM SPARK_REGISTRATIONS LIMIT 10000", ())
    all_regs = [_from_hana(r) for r in all_rows]

    processed, skipped = 0, 0
    for sess in sessions_docs:
        title = sess.get("title", "").strip()
        if not title:
            continue
        sess_regs = [r for r in all_regs if r.get("session") == title]
        if not sess_regs:
            skipped += 1
            continue

        area = sess.get("area", "")
        l1_areas = list(set(l for a in ([area] if area else []) for l in _SPARK_TO_L1.get(a, [])))

        orgs: dict[str, list] = {}
        org_domains_b: dict[str, list] = {}
        for reg in sess_regs:
            org = (reg.get("organization") or reg.get("org") or "Unknown").strip()
            orgs.setdefault(org, []).append({
                "name":         reg.get("name", ""),
                "email":        reg.get("email", ""),
                "country":      reg.get("country", ""),
                "role":         reg.get("role") or reg.get("function", ""),
                "attended":     reg.get("attended", False),
                "session":      title,
                "session_date": reg.get("sessionDate") or reg.get("session_date", ""),
                "sapContact":   reg.get("sapContact"),
            })
            email = (reg.get("email") or "").strip().lower()
            if "@" in email:
                domain = email.split("@", 1)[1]
                if domain and domain not in _PERSONAL:
                    org_domains_b.setdefault(org, [])
                    if domain not in org_domains_b[org]:
                        org_domains_b[org].append(domain)

        semaphore = asyncio.Semaphore(8)

        async def _classify_with_sem_batch(org: str):
            async with semaphore:
                async with httpx.AsyncClient(timeout=15) as c:
                    try:
                        result = await _classify_org(c, org, l1_areas,
                                                     email_domains=org_domains_b.get(org, []))
                    except Exception as exc:
                        print(f"[batch] classify error for '{org}': {exc}", flush=True)
                        result = {"classification": "unknown", "open_opps": 0, "pipeline": [],
                                  "installed_solutions": [], "installed_products": [], "installed_by_l1": {},
                                  "top_contacts": [], "account_bp": None,
                                  "ae": None, "ae_email": None, "flsm": None,
                                  "region": None, "aes": [], "ae_emails": [], "flsms": [], "regions": []}
                    return {"organization": org, "participants": orgs[org], **result}

        companies = list(await asyncio.gather(*[_classify_with_sem_batch(o) for o in orgs]))
        order = {"potential_lead": 0, "maturation": 1, "adoption": 2, "unknown": 3}
        companies.sort(key=lambda x: order.get(x.get("classification", "unknown"), 3))

        slug = re.sub(r"[^a-z0-9]+", "-", title.lower())[:80]
        snap_data = {
            "id":          slug,
            "session":     title,
            "sessionArea": area,
            "analyzedAt":  datetime.now(timezone.utc).isoformat(),
            "companies":   json.dumps(companies),
            "summary":     json.dumps({
                "potential_lead": sum(1 for co in companies if co.get("classification") == "potential_lead"),
                "maturation":     sum(1 for co in companies if co.get("classification") == "maturation"),
                "adoption":       sum(1 for co in companies if co.get("classification") == "adoption"),
                "total":          len(sess_regs),
            }),
        }
        await _hx(
            "UPSERT SPARK_INTELLIGENCE_SNAPSHOTS (id, session, session_area, analyzed_at, data_json) "
            "VALUES (?, ?, ?, ?, ?) WITH PRIMARY KEY",
            (slug, title, area[:256], snap_data["analyzedAt"], json.dumps(snap_data))
        )
        processed += 1

    return {"ok": True, "processed": processed, "skipped": skipped,
            "analyzedAt": datetime.now(timezone.utc).isoformat()}


# ── Intelligence: list snapshots ──────────────────────────────────────────────

@app.get("/api/intelligence/snapshots")
async def list_intelligence_snapshots(request: Request):
    _check_api_key(request)
    rows = await _hq(
        "SELECT id, data_json FROM SPARK_INTELLIGENCE_SNAPSHOTS "
        "ORDER BY analyzed_at DESC LIMIT 200", ()
    )
    result = []
    for row in rows:
        d = _from_hana(row)
        summary_raw = d.get("summary", {})
        summary = json.loads(summary_raw) if isinstance(summary_raw, str) else summary_raw
        result.append({
            "session":     d.get("session", ""),
            "sessionArea": d.get("sessionArea", ""),
            "analyzedAt":  d.get("analyzedAt", ""),
            "summary":     summary,
        })
    return result


# ── Intelligence: read snapshot data for selected sessions ────────────────────

@app.get("/api/intelligence/snapshot-data")
async def get_intelligence_snapshot_data(request: Request, session: list[str] = Query(default=[])):
    _check_api_key(request)
    if not session:
        raise HTTPException(status_code=400, detail="At least one session required")

    session_set = set(session)
    rows = await _hq("SELECT id, data_json FROM SPARK_INTELLIGENCE_SNAPSHOTS LIMIT 500", ())

    companies_merged: dict[str, dict] = {}
    session_areas: list[str] = []

    for row in rows:
        d = _from_hana(row)
        sess_title = d.get("session", "")
        if sess_title not in session_set:
            continue
        area = d.get("sessionArea", "")
        if area and area not in session_areas:
            session_areas.append(area)
        companies_raw = d.get("companies", [])
        companies = json.loads(companies_raw) if isinstance(companies_raw, str) else companies_raw
        for co in companies:
            org = co.get("organization", "Unknown")
            if org not in companies_merged:
                companies_merged[org] = {**co, "sessions": [sess_title]}
            else:
                existing = companies_merged[org]
                order_map = {"adoption": 0, "maturation": 1, "potential_lead": 2, "unknown": 3}
                if order_map.get(co.get("classification"), 3) < order_map.get(existing.get("classification"), 3):
                    companies_merged[org]["classification"] = co["classification"]
                existing["sessions"].append(sess_title)
                # Keep all attendance records — one entry per (participant × session).
                # Do NOT deduplicate by email: the same person attending 3 sessions = 3 rows.
                existing["participants"].extend(co.get("participants", []))
                existing["open_opps"] = existing.get("open_opps", 0) + co.get("open_opps", 0)

    companies_list = list(companies_merged.values())
    order = {"potential_lead": 0, "maturation": 1, "adoption": 2, "unknown": 3}
    companies_list.sort(key=lambda x: order.get(x.get("classification", "unknown"), 3))

    return {
        "sessions":      list(session),
        "session_areas": session_areas,
        "companies":     companies_list,
        "total":         sum(len(co.get("participants", [])) for co in companies_list),
        "summary": {
            "potential_lead": sum(1 for co in companies_list if co.get("classification") == "potential_lead"),
            "maturation":     sum(1 for co in companies_list if co.get("classification") == "maturation"),
            "adoption":       sum(1 for co in companies_list if co.get("classification") == "adoption"),
        },
    }


# ── Intelligence: send email to AE via ESS ───────────────────────────────────



async def _get_ess_template(key: str) -> tuple[str, str]:
    """Return (container_id, slot_id) for the given key, falling back to any configured template."""
    tmpl = _ESS_TEMPLATES.get(key)
    if not tmpl or not tmpl.get("container"):
        tmpl = next((t for t in _ESS_TEMPLATES.values() if t.get("container")), None)
    if not tmpl or not tmpl.get("container"):
        raise RuntimeError(
            "No ESS template configured. Configure at least one template in ESS Settings."
        )
    return tmpl["container"], tmpl.get("slot", "body")


class IntelEmailRequest(BaseModel):
    ae_name: str
    ae_email: str
    flsm_name: str = ""
    flsm_email: str = ""
    sessions: list[str]
    companies: list[dict]   # pre-filtered by AE, sent from frontend


@app.post("/api/intelligence/send-email")
async def send_intelligence_email(request: Request, body: IntelEmailRequest):
    _check_api_key(request)

    leads      = [co for co in body.companies if co.get("classification") == "potential_lead"]
    maturation = [co for co in body.companies if co.get("classification") == "maturation"]
    adoption   = [co for co in body.companies if co.get("classification") == "adoption"]

    def _co_block(co: dict) -> str:
        parts = co.get("participants", [])
        attended = sum(1 for p in parts if p.get("attended"))
        names    = ", ".join(p["name"] for p in parts[:3] if p.get("name"))
        opps     = co.get("open_opps", 0)
        opp_str  = f"<br><small style='color:#666;'>Open opps: {opps}</small>" if opps else ""
        return (f"<li style='margin-bottom:6px;'><b>{co['organization']}</b> — "
                f"{len(parts)} participant(s), {attended} attended"
                f"<br><small style='color:#888;'>{names}</small>{opp_str}</li>")

    html = f"""
<div style="font-family:Arial,sans-serif;font-size:14px;color:#222;max-width:680px;">
  <p>Dear {body.ae_name.split()[0] if body.ae_name else 'colleague'},</p>
  <p>Below is a summary of customers who participated in recent <b>Digital Discover Expert Meeting</b> sessions
     related to your accounts. Please find their classification based on pipeline and installed-base data.</p>
  <p><b>Sessions covered:</b> {', '.join(body.sessions)}</p>
  <hr style="border:none;border-top:1px solid #eee;margin:16px 0;">
"""
    if leads:
        html += f"""
  <h3 style="color:#E74C3C;margin-bottom:6px;">Potential Leads ({len(leads)})</h3>
  <p style="font-size:12px;color:#666;margin-top:0;">No open opportunity and no installed SAP solution — highest priority to open.</p>
  <ul style="padding-left:18px;">{"".join(_co_block(co) for co in leads)}</ul>
"""
    if maturation:
        html += f"""
  <h3 style="color:#2980B9;margin-bottom:6px;">Maturation ({len(maturation)})</h3>
  <p style="font-size:12px;color:#666;margin-top:0;">Open opportunity in pipeline — follow up to advance the deal.</p>
  <ul style="padding-left:18px;">{"".join(_co_block(co) for co in maturation)}</ul>
"""
    if adoption:
        html += f"""
  <h3 style="color:#27AE60;margin-bottom:6px;">Adoption ({len(adoption)})</h3>
  <p style="font-size:12px;color:#666;margin-top:0;">Already using a relevant SAP solution — expansion or upsell opportunity.</p>
  <ul style="padding-left:18px;">{"".join(_co_block(co) for co in adoption)}</ul>
"""
    html += """
  <hr style="border:none;border-top:1px solid #eee;margin:16px 0;">
  <p style="font-size:12px;color:#888;">Generated by DDE Meeting · Digital Discovery Expert Series LAC</p>
</div>"""

    subject = f"DDE Meeting – Intelligence Report – {body.ae_name}"
    ess_container, ess_slot = await _get_ess_template("default")

    await _ess_send_email(body.ae_email, body.ae_name, subject, html, ess_container, ess_slot)

    if body.flsm_email:
        await _ess_send_email(body.flsm_email, body.flsm_name or body.flsm_email,
                              subject + " [CC: Manager]", html, ess_container, ess_slot)

    return {"ok": True, "sent_to": [body.ae_email] + ([body.flsm_email] if body.flsm_email else [])}


# ── Intelligence — EML download tracking ────────────────────────────────────

class IntelMarkSentRequest(BaseModel):
    ae_name: str
    ae_email: str
    sessions: list[str]
    companies: list[str]   # organization names


@app.post("/api/intelligence/mark-sent")
async def intel_mark_sent(request: Request, body: IntelMarkSentRequest):
    _check_api_key(request)
    import hashlib
    key_src = body.ae_email.lower() + "|" + "|".join(sorted(body.sessions))
    job_id  = hashlib.sha1(key_src.encode()).hexdigest()[:20]
    now     = datetime.now(timezone.utc).isoformat()
    await _hx(
        "UPSERT SPARK_EMAIL_JOBS "
        "(id, status, to_email, to_name, subject, html, container, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) WITH PRIMARY KEY",
        (
            job_id,
            "downloaded",
            body.ae_email,
            body.ae_name,
            json.dumps(body.sessions),
            json.dumps(body.companies),
            "intelligence-download",
            now,
            now,
        )
    )
    return {"ok": True, "id": job_id}


@app.get("/api/intelligence/sent-log")
async def intel_sent_log(request: Request):
    _check_api_key(request)
    rows = await _hq(
        "SELECT id, to_email, to_name, subject, html, updated_at "
        "FROM SPARK_EMAIL_JOBS WHERE container='intelligence-download' "
        "ORDER BY updated_at DESC"
    )
    result = []
    for r in rows:
        try:
            sessions = json.loads(r.get("subject") or "[]")
        except Exception:
            sessions = []
        try:
            companies = json.loads(r.get("html") or "[]")
        except Exception:
            companies = []
        result.append({
            "id":           r.get("id"),
            "ae_email":     r.get("to_email"),
            "ae_name":      r.get("to_name"),
            "sessions":     sessions,
            "companies":    companies,
            "downloaded_at": r.get("updated_at"),
        })
    return result



class AzureCallbackRequest(BaseModel):
    code: str
    redirect_uri: str

@app.post("/api/auth/azure")
async def auth_azure(body: AzureCallbackRequest):
    # 1. Troca auth code por tokens no Entra
    token_url = f"https://login.microsoftonline.com/{_AZURE_TENANT_ID}/oauth2/v2.0/token"
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.post(token_url, data={
            "grant_type":    "authorization_code",
            "client_id":     _AZURE_CLIENT_ID,
            "client_secret": _AZURE_CLIENT_SECRET,
            "code":          body.code,
            "redirect_uri":  body.redirect_uri,
            "scope":         "openid profile email User.Read",
        })
    if not resp.is_success:
        raise HTTPException(status_code=401, detail=f"Azure token exchange failed: {resp.text[:200]}")

    # 2. Busca perfil no Microsoft Graph
    access_token = resp.json().get("access_token", "")
    async with httpx.AsyncClient(timeout=10) as c:
        graph = await c.get("https://graph.microsoft.com/v1.0/me",
                            headers={"Authorization": f"Bearer {access_token}"})
    if not graph.is_success:
        raise HTTPException(status_code=401, detail="Failed to fetch profile from Microsoft Graph")

    profile = graph.json()
    email = (profile.get("mail") or profile.get("userPrincipalName") or "").lower().strip()
    name  = profile.get("displayName") or email.split("@")[0]
    if not email:
        raise HTTPException(status_code=401, detail="Could not get email from Microsoft profile")

    # 3. Lookup ou auto-provisioning no HANA
    rows = await _hq("SELECT id, data_json FROM SPARK_USERS WHERE email = ?", (email,))
    user = _from_hana(rows[0]) if rows else None

    if not user:
        user_id = _uuid.uuid4().hex
        data = {"id": user_id, "email": email, "name": name, "password_hash": "",
                "approved": True, "role": "user", "modules": [],
                "created_at": datetime.now(timezone.utc).isoformat(), "sso": "azure"}
        await _upsert_user(user_id, data)
        user = data

    role = user.get("role", "user")
    if email == _ADMIN_EMAIL:
        role = "admin"
    modules = user.get("modules", [])

    token = _make_token(user.get("id", email), email, name, role)
    return {"ok": True, "name": name, "email": email,
            "token": token, "role": role, "modules": modules, "expires_in": _JWT_EXPIRY}

@app.get("/auth/callback")
async def azure_callback():
    from fastapi.responses import FileResponse
    return FileResponse(os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html"))

# ── Activity Log ──────────────────────────────────────────────────────────────

async def _ensure_activity_table():
    try:
        await _hx(
            "CREATE TABLE SPARK_ACTIVITY_LOG ("
            "id VARCHAR(64) PRIMARY KEY, user_email VARCHAR(256), user_name NCLOB, "
            "action VARCHAR(128), entity VARCHAR(128), entity_id VARCHAR(256), "
            "detail NCLOB, created_at VARCHAR(64))"
        )
    except Exception as e:
        if not _hana_is_dup(e):
            raise

@app.post("/api/activity")
async def log_activity(request: Request):
    _check_api_key(request)
    body = await request.json()
    entry_id = hashlib.sha1(f"{body.get('action','')}_{body.get('entity_id','')}_{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()[:24]
    await _ensure_activity_table()
    await _hx(
        "INSERT INTO SPARK_ACTIVITY_LOG (id, user_email, user_name, action, entity, entity_id, detail, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (entry_id, body.get("user_email",""), body.get("user_name",""),
         body.get("action",""), body.get("entity",""), body.get("entity_id",""),
         body.get("detail",""), datetime.now(timezone.utc).isoformat())
    )
    return {"ok": True, "id": entry_id}

@app.get("/api/activity")
async def get_activity(request: Request, limit: int = 200):
    _check_api_key(request)
    await _ensure_activity_table()
    rows = await _hq(
        "SELECT id, user_email, user_name, action, entity, entity_id, detail, created_at "
        "FROM SPARK_ACTIVITY_LOG ORDER BY created_at DESC LIMIT ?", (limit,)
    )
    return rows

@app.delete("/api/activity")
async def clear_activity(request: Request):
    _check_api_key(request)
    await _ensure_activity_table()
    await _hx("DELETE FROM SPARK_ACTIVITY_LOG")
    return {"ok": True}

# ── List Sources ──────────────────────────────────────────────────────────────

async def _ensure_sources_table():
    try:
        await _hx(
            "CREATE TABLE SPARK_LIST_SOURCES ("
            "id VARCHAR(64) PRIMARY KEY, name NCLOB, description NCLOB, created_at VARCHAR(64))"
        )
    except Exception as e:
        if not _hana_is_dup(e):
            raise

@app.get("/api/list-sources")
async def get_list_sources(request: Request):
    _check_api_key(request)
    await _ensure_sources_table()
    rows = await _hq("SELECT id, name, description, created_at FROM SPARK_LIST_SOURCES ORDER BY created_at DESC", ())
    return rows

@app.post("/api/list-sources", status_code=201)
async def create_list_source(request: Request):
    _check_api_key(request)
    body = await request.json()
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    src_id = hashlib.sha1(name.lower().encode()).hexdigest()[:16]
    await _ensure_sources_table()
    await _hx(
        "UPSERT SPARK_LIST_SOURCES (id, name, description, created_at) VALUES (?, ?, ?, ?) WITH PRIMARY KEY",
        (src_id, name, (body.get("description") or "").strip(), datetime.now(timezone.utc).isoformat())
    )
    return {"ok": True, "id": src_id, "name": name}

@app.delete("/api/list-sources/{src_id}", status_code=204)
async def delete_list_source(request: Request, src_id: str):
    _check_api_key(request)
    await _hx("DELETE FROM SPARK_LIST_SOURCES WHERE id = ?", (src_id,))

# ── Campaigns ─────────────────────────────────────────────────────────────────

async def _ensure_campaign_tables():
    try:
        await _hx(
            "CREATE TABLE SPARK_CAMPAIGNS ("
            "id VARCHAR(64) PRIMARY KEY, name NCLOB, lob VARCHAR(128), "
            "description NCLOB, created_at VARCHAR(64), contact_count INTEGER DEFAULT 0)"
        )
    except Exception as e:
        if not _hana_is_dup(e):
            raise
    for col_ddl in [
        "ALTER TABLE SPARK_CAMPAIGNS ADD (owner VARCHAR(256))",
        "ALTER TABLE SPARK_CAMPAIGNS ADD (start_date VARCHAR(32))",
        "ALTER TABLE SPARK_CAMPAIGNS ADD (end_date VARCHAR(32))",
        "ALTER TABLE SPARK_CAMPAIGN_CONTACTS ADD (erp VARCHAR(128))",
        "ALTER TABLE SPARK_CAMPAIGN_CONTACTS ADD (campaign_ref NCLOB)",
        "ALTER TABLE SPARK_CAMPAIGN_CONTACTS ADD (invited_at VARCHAR(64))",
    ]:
        try:
            await _hx(col_ddl)
        except Exception as e:
            if not _hana_is_dup(e):
                raise
    try:
        await _hx(
            "CREATE TABLE SPARK_CAMPAIGN_CONTACTS ("
            "id VARCHAR(64) PRIMARY KEY, campaign_id VARCHAR(64), "
            "planning_entity_name NCLOB, first_name NCLOB, last_name NCLOB, "
            "email_norm VARCHAR(256), full_name_norm NCLOB, title NCLOB, "
            "ae VARCHAR(256), lob VARCHAR(128), sde VARCHAR(256), "
            "persona NCLOB, data_json NCLOB)"
        )
    except Exception as e:
        if not _hana_is_dup(e):
            raise

@app.get("/api/campaigns")
async def list_campaigns(request: Request):
    _check_api_key(request)
    await _ensure_campaign_tables()
    camps = await _hq(
        "SELECT c.id, c.name, c.lob, c.description, c.created_at, "
        "c.owner, c.start_date, c.end_date, "
        "COALESCE(cnt.contact_count, 0) AS contact_count "
        "FROM SPARK_CAMPAIGNS c "
        "LEFT JOIN (SELECT campaign_id, COUNT(*) AS contact_count FROM SPARK_CAMPAIGN_CONTACTS GROUP BY campaign_id) cnt "
        "ON cnt.campaign_id = c.id "
        "ORDER BY c.created_at DESC", ()
    )
    return camps

@app.post("/api/campaigns", status_code=201)
async def create_campaign(request: Request):
    _check_api_key(request)
    body = await request.json()
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    camp_id = hashlib.sha1(f"{name}_{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()[:20]
    await _ensure_campaign_tables()
    await _hx(
        "INSERT INTO SPARK_CAMPAIGNS (id, name, lob, description, owner, start_date, end_date, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (camp_id, name, (body.get("lob") or "").strip(),
         (body.get("description") or "").strip(),
         (body.get("owner") or "").strip(),
         (body.get("start_date") or "").strip(),
         (body.get("end_date") or "").strip(),
         datetime.now(timezone.utc).isoformat())
    )
    return {"ok": True, "id": camp_id, "name": name}

@app.get("/api/campaigns/{camp_id}/match")
async def get_campaign_matches(request: Request, camp_id: str):
    _check_api_key(request)
    contacts = await _hq(
        "SELECT email_norm, first_name, last_name, planning_entity_name, title, ae, lob "
        "FROM SPARK_CAMPAIGN_CONTACTS WHERE campaign_id = ?", (camp_id,)
    )
    if not contacts:
        return {"total": 0, "registered": 0, "contacts": []}
    emails = list({c["email_norm"] for c in contacts if c.get("email_norm")})
    reg_map: dict = {}
    if emails:
        placeholders = ",".join(["?" for _ in emails])
        regs = await _hq(
            f"SELECT email, session, data_json FROM SPARK_REGISTRATIONS WHERE email IN ({placeholders})",
            tuple(emails)
        )
        for r in regs:
            d = json.loads(r.get("data_json") or "{}")
            entry = {
                "session": r.get("session") or d.get("session", ""),
                "session_date": d.get("sessionDate") or d.get("session_date", ""),
                "attended": bool(d.get("attended", False)),
            }
            reg_map.setdefault(r["email"], []).append(entry)
    result = []
    for c in contacts:
        email = c.get("email_norm", "")
        sessions = reg_map.get(email, [])
        result.append({
            "first_name": c.get("first_name") or "",
            "last_name": c.get("last_name") or "",
            "email": email,
            "company": c.get("planning_entity_name") or "",
            "title": c.get("title") or "",
            "ae": c.get("ae") or "",
            "lob": c.get("lob") or "",
            "registered": len(sessions) > 0,
            "sessions": sessions,
        })
    result.sort(key=lambda x: (not x["registered"], x.get("company", "").lower(), x.get("last_name", "").lower()))
    return {"total": len(result), "registered": sum(1 for c in result if c["registered"]), "contacts": result}

@app.patch("/api/campaigns/{camp_id}")
async def update_campaign(request: Request, camp_id: str):
    _check_api_key(request)
    body = await request.json()
    fields = {}
    if "name" in body:
        name = (body["name"] or "").strip()
        if not name:
            raise HTTPException(status_code=400, detail="name cannot be empty")
        fields["name"] = name
    for f in ("description", "owner", "start_date", "end_date"):
        if f in body:
            fields[f] = (body[f] or "").strip()
    if not fields:
        return {"ok": True}
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    await _hx(f"UPDATE SPARK_CAMPAIGNS SET {set_clause} WHERE id = ?", (*fields.values(), camp_id))
    return {"ok": True}

@app.delete("/api/campaigns/{camp_id}", status_code=204)
async def delete_campaign(request: Request, camp_id: str):
    _check_api_key(request)
    await _hx("DELETE FROM SPARK_CAMPAIGN_CONTACTS WHERE campaign_id = ?", (camp_id,))
    await _hx("DELETE FROM SPARK_CAMPAIGNS WHERE id = ?", (camp_id,))

@app.get("/api/campaigns/{camp_id}/contacts")
async def get_campaign_contacts(request: Request, camp_id: str):
    _check_api_key(request)
    rows = await _hq(
        "SELECT id, planning_entity_name, first_name, last_name, title, ae, lob, sde, persona, erp, campaign_ref, invited_at, data_json "
        "FROM SPARK_CAMPAIGN_CONTACTS WHERE campaign_id = ? ORDER BY id",
        (camp_id,)
    )
    result = []
    for r in rows:
        d = json.loads(r.get("data_json") or "{}")
        d["full_name"] = f"{r.get('first_name','')} {r.get('last_name','')}".strip()
        d.update({k: r[k] for k in ("id","planning_entity_name","first_name","last_name","title","ae","lob","sde","persona","erp","campaign_ref","invited_at") if r.get(k) is not None})
        result.append(d)
    return result

@app.delete("/api/campaigns/{camp_id}/contacts", status_code=200)
async def clear_campaign_contacts(request: Request, camp_id: str):
    _check_api_key(request)
    await _ensure_campaign_tables()
    await _hx("DELETE FROM SPARK_CAMPAIGN_CONTACTS WHERE campaign_id = ?", (camp_id,))
    return {"ok": True}


def _build_campaign_invite_html(name: str, lang: str, campaign_name: str = "") -> str:
    site = _SITE_URL
    event = campaign_name or "Digital Discovery Expert Series"
    if lang == "pt":
        headline = f"Você está convidado!"
        body = (f"Olá, <strong>{name}</strong>!<br><br>"
                f"Temos o prazer de convidar você para participar do <strong>{event}</strong>, "
                f"uma série de sessões exclusivas desenvolvida para líderes de negócios e TI.<br><br>"
                f"Acesse o link abaixo para garantir sua vaga e conferir a agenda completa.")
        cta = "Garantir Minha Vaga"
    else:
        headline = f"¡Estás invitado!"
        body = (f"Hola, <strong>{name}</strong>!<br><br>"
                f"Tenemos el placer de invitarte a participar en <strong>{event}</strong>, "
                f"una serie de sesiones exclusivas diseñada para líderes de negocio y TI.<br><br>"
                f"Accede al enlace a continuación para reservar tu lugar y ver la agenda completa.")
        cta = "Reservar Mi Lugar"
    btn = (f'<a href="{site}" style="display:inline-block;padding:12px 28px;background:#0070F2;'
           f'color:#ffffff;text-decoration:none;border-radius:6px;font-weight:700;font-size:14px;">'
           f'{cta}</a>')
    return (f'<p style="font-size:22px;font-weight:700;color:#001E2B;margin:0 0 16px">{headline}</p>'
            f'<p style="font-size:14px;color:#223548;line-height:1.7;margin:0 0 24px">{body}</p>'
            f'{btn}')


@app.post("/api/campaigns/{camp_id}/send-invites")
async def send_campaign_invites(request: Request, camp_id: str):
    _check_api_key(request)
    body = await request.json()
    contact_ids: list = body.get("contact_ids", [])
    subject_override: str = body.get("subject", "").strip()
    template_key: str = body.get("template", "invite")

    if not contact_ids:
        raise HTTPException(status_code=400, detail="contact_ids must be a non-empty list")

    camps = await _hq("SELECT id, name FROM SPARK_CAMPAIGNS WHERE id = ?", (camp_id,))
    if not camps:
        raise HTTPException(status_code=404, detail="Campaign not found")
    camp_name = camps[0].get("name", "")

    placeholders = ",".join(["?" for _ in contact_ids])
    rows = await _hq(
        f"SELECT id, data_json FROM SPARK_CAMPAIGN_CONTACTS "
        f"WHERE campaign_id = ? AND id IN ({placeholders})",
        (camp_id, *contact_ids)
    )

    sent, failed, results = 0, 0, []
    now_ts = datetime.now(timezone.utc).isoformat()[:10]

    for r in rows:
        d = json.loads(r.get("data_json") or "{}")
        to_email = (d.get("email") or "").strip()
        to_name  = (d.get("name") or f"{d.get('first_name','')} {d.get('last_name','')}".strip() or to_email)
        if not to_email:
            results.append({"id": r["id"], "ok": False, "error": "No email"})
            failed += 1
            continue

        lang = "pt" if to_email.lower().endswith(".com.br") or to_email.lower().endswith(".br") else "es"
        tmpl = (_ESS_TEMPLATES.get(f"{template_key}_{lang}")
                or _ESS_TEMPLATES.get(f"{template_key}_pt")
                or _ESS_TEMPLATES.get("rsvp_pt", {}))
        container = tmpl.get("container", "")
        slot      = tmpl.get("slot", "body")

        if lang == "pt":
            subject = subject_override or f"Convite – {camp_name}"
        else:
            subject = subject_override or f"Invitación – {camp_name}"

        html = _build_campaign_invite_html(to_name, lang, camp_name)
        try:
            await _ess_send_email(to_email, to_name, subject, html, container, slot)
            await _hx("UPDATE SPARK_CAMPAIGN_CONTACTS SET invited_at = ? WHERE id = ?",
                      (now_ts, r["id"]))
            results.append({"id": r["id"], "ok": True, "to": to_email, "name": to_name})
            sent += 1
        except Exception as exc:
            results.append({"id": r["id"], "ok": False, "error": str(exc)[:200]})
            failed += 1

    return {"sent": sent, "failed": failed, "results": results}

@app.post("/api/campaigns/{camp_id}/upload")
async def upload_campaign_contacts(request: Request, camp_id: str, file: UploadFile = File(...)):
    _check_api_key(request)
    try:
        import openpyxl, io
    except ImportError:
        raise HTTPException(status_code=500, detail="openpyxl not installed")

    camps = await _hq("SELECT id FROM SPARK_CAMPAIGNS WHERE id = ?", (camp_id,))
    if not camps:
        raise HTTPException(status_code=404, detail="Campaign not found")

    contents = await file.read()
    wb = openpyxl.load_workbook(io.BytesIO(contents), read_only=True, data_only=True)
    ws = wb.active
    rows = list(ws.iter_rows(values_only=True))
    if len(rows) < 2:
        raise HTTPException(status_code=400, detail="File has fewer than 2 rows")

    headers = [str(h).strip() if h is not None else "" for h in rows[0]]
    col = {name: idx for idx, name in enumerate(headers)}

    def _g(row, key, default=""):
        idx = col.get(key)
        if idx is None: return default
        v = row[idx] if idx < len(row) else None
        if v is None: return default
        # integers from Excel (e.g. Planning Entity ID) should not become "7416694.0"
        if isinstance(v, float) and v == int(v):
            return str(int(v)).strip()
        return str(v).strip()

    inserted = 0
    skipped = 0
    await _ensure_campaign_tables()

    ops: list[tuple] = [
        ("DELETE FROM SPARK_CAMPAIGN_CONTACTS WHERE campaign_id = ?", (camp_id,))
    ]
    for row in rows[1:]:
        email_raw = _g(row, "Email").lower().strip() or _g(row, "Email Address").lower().strip()
        first = _g(row, "First Name")
        last  = _g(row, "Last Name")
        if not email_raw and not first and not last:
            skipped += 1
            continue
        full_name = f"{first} {last}".strip()
        contact_id = hashlib.sha1(f"{camp_id}_{email_raw}_{full_name}".encode()).hexdigest()[:24]
        data = {
            "email": email_raw,
            "first_name": first,
            "last_name": last,
            "name": full_name,
            "planning_entity_id": _g(row, "Planning Entity ID"),
            "planning_entity_name": _g(row, "Planning Entity Name"),
            "title": _g(row, "Title"),
            "ae": _g(row, "AE"),
            "lob": _g(row, "LoB"),
            "sde": _g(row, "SDE"),
            "persona": _g(row, "Persona Name"),
            "campaign_ref": _g(row, "Campaña"),
            "erp": _g(row, "ERP"),
            "prospect_link": _g(row, "Link Prospects"),
            "campaign_id": camp_id,
        }
        email_norm = email_raw[:256]
        name_norm = _norm_name(full_name)[:512]
        ops.append((
            "UPSERT SPARK_CAMPAIGN_CONTACTS (id, campaign_id, planning_entity_name, first_name, last_name, "
            "email_norm, full_name_norm, title, ae, lob, sde, persona, erp, campaign_ref, data_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) WITH PRIMARY KEY",
            (contact_id, camp_id, data["planning_entity_name"][:2000], first[:256], last[:256],
             email_norm, name_norm, data["title"][:512], data["ae"][:256],
             data["lob"][:128], data["sde"][:256], data["persona"][:512],
             data["erp"][:128], data["campaign_ref"][:512], json.dumps(data))
        ))
        inserted += 1

    await _hx_txn(ops)
    return {"ok": True, "inserted": inserted, "skipped": skipped}

@app.get("/api/campaigns/match")
async def match_campaign_contact(request: Request, email: str = "", name: str = ""):
    """Check if an email or name matches any campaign contact. Returns matched campaign info."""
    _check_api_key(request)
    email_norm = (email or "").lower().strip()
    name_norm = _norm_name(name)
    if not email_norm and not name_norm:
        return []

    matches = []
    if email_norm:
        rows = await _hq(
            "SELECT cc.campaign_id, cc.data_json, c.name AS campaign_name "
            "FROM SPARK_CAMPAIGN_CONTACTS cc JOIN SPARK_CAMPAIGNS c ON c.id = cc.campaign_id "
            "WHERE cc.email_norm = ?", (email_norm,)
        )
        for r in rows:
            d = json.loads(r.get("data_json") or "{}")
            matches.append({"campaign_id": r["campaign_id"], "campaign_name": r["campaign_name"],
                            "match_type": "email", "contact": d})

    if not matches and name_norm:
        rows = await _hq(
            "SELECT cc.campaign_id, cc.full_name_norm, cc.data_json, c.name AS campaign_name "
            "FROM SPARK_CAMPAIGN_CONTACTS cc JOIN SPARK_CAMPAIGNS c ON c.id = cc.campaign_id", ()
        )
        for r in rows:
            sim = _name_similarity(name_norm, r.get("full_name_norm",""))
            if sim >= 0.82:
                d = json.loads(r.get("data_json") or "{}")
                matches.append({"campaign_id": r["campaign_id"], "campaign_name": r["campaign_name"],
                                "match_type": "name", "similarity": round(sim, 2), "contact": d})

    return matches

# ── Presence ──────────────────────────────────────────────────────────────────
_presence_table_ready = False

async def _ensure_presence_table():
    global _presence_table_ready
    if _presence_table_ready:
        return
    try:
        await _hx(
            "CREATE TABLE SPARK_PRESENCE ("
            "  user_id VARCHAR(128) PRIMARY KEY,"
            "  user_email VARCHAR(256),"
            "  user_name NCLOB,"
            "  last_seen VARCHAR(64)"
            ")"
        )
    except Exception:
        pass  # table already exists
    _presence_table_ready = True

@app.post("/api/presence/heartbeat")
async def presence_heartbeat(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Auth required")
    payload = _verify_token(auth[7:])
    user_id    = payload.get("sub", "")
    user_email = payload.get("email", "")
    user_name  = payload.get("name", "")
    now = datetime.now(timezone.utc).isoformat()
    await _ensure_presence_table()
    await _hx(
        "UPSERT SPARK_PRESENCE (user_id, user_email, user_name, last_seen) VALUES (?, ?, ?, ?) WITH PRIMARY KEY",
        (user_id, user_email, user_name, now)
    )
    return {"ok": True}

@app.get("/api/presence")
async def get_presence(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Auth required")
    _verify_token(auth[7:])
    await _ensure_presence_table()
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    rows = await _hq(
        "SELECT user_email, user_name, last_seen FROM SPARK_PRESENCE WHERE last_seen >= ? ORDER BY last_seen DESC",
        (cutoff,)
    )
    return rows

# ── CRM Leads ─────────────────────────────────────────────────────────────────

async def _ensure_crm_sessions_table():
    try:
        await _hx(
            "CREATE TABLE SPARK_CRM_SESSIONS ("
            "id VARCHAR(64) PRIMARY KEY, "
            "title NVARCHAR(512), "
            "description NCLOB, "
            "solution_area VARCHAR(128), "
            "target_audience NVARCHAR(256), "
            "regions NVARCHAR(256), "
            "language VARCHAR(16), "
            "solution_advisor NVARCHAR(256), "
            "advisor_email VARCHAR(256), "
            "agenda_created VARCHAR(8), "
            "invite_created VARCHAR(8), "
            "presentation_date VARCHAR(32), "
            "crm_id VARCHAR(128), "
            "wrike_request VARCHAR(128), "
            "ptt_id VARCHAR(128), "
            "link_registro NCLOB, "
            "imported_at VARCHAR(64)"
            ")"
        )
    except Exception as e:
        if not _hana_is_dup(e):
            raise

async def _ensure_crm_leads_table():
    try:
        await _hx(
            "CREATE TABLE SPARK_CRM_LEADS ("
            "id VARCHAR(64) PRIMARY KEY, "
            "fecha NVARCHAR(128), "
            "sesion NVARCHAR(512), "
            "empresa NVARCHAR(512), "
            "notas NCLOB, "
            "producto NCLOB, "
            "account_id VARCHAR(128), "
            "crm_id VARCHAR(128), "
            "lead_id VARCHAR(128), "
            "mu NVARCHAR(256), "
            "pais NVARCHAR(256), "
            "lob VARCHAR(128), "
            "sales_qualifier NVARCHAR(512), "
            "status VARCHAR(128), "
            "imported_at VARCHAR(64)"
            ")"
        )
    except Exception as e:
        if not _hana_is_dup(e):
            raise

@app.post("/api/crm-leads/import")
async def import_crm_leads(request: Request, file: UploadFile = File(...)):
    _check_api_key(request)
    import openpyxl, io as _io
    contents = await file.read()
    wb = openpyxl.load_workbook(_io.BytesIO(contents), read_only=True, data_only=True)
    now_ts = datetime.now(timezone.utc).isoformat()

    def _get(row, col_map, key: str) -> str:
        idx = col_map.get(key)
        if idx is None or idx >= len(row):
            return ""
        v = row[idx]
        if v is None:
            return ""
        return str(v).strip()

    sessions_imported = sessions_dup = sessions_skipped = 0
    leads_imported = leads_dup = leads_skipped = 0

    # ── Sheet1: sessions ──────────────────────────────────────────────────────
    sheet1 = None
    for name in wb.sheetnames:
        if name.strip().upper() in ("SHEET1", "SHEET 1"):
            sheet1 = wb[name]
            break
    if sheet1 is None and wb.sheetnames:
        # fallback: first sheet that looks like sessions (has "Title" + "CRM ID")
        for name in wb.sheetnames:
            ws_tmp = wb[name]
            first_row = next(ws_tmp.iter_rows(values_only=True, max_row=1), ())
            cells = [str(c).strip() if c else "" for c in first_row]
            if "Title" in cells and "CRM ID" in cells:
                sheet1 = ws_tmp
                break

    if sheet1:
        rows1 = list(sheet1.iter_rows(values_only=True))
        if rows1:
            headers1 = [str(c).strip() if c is not None else "" for c in rows1[0]]
            col1 = {h: i for i, h in enumerate(headers1)}
            await _ensure_crm_sessions_table()
            for row in rows1[1:]:
                if all(v is None for v in row):
                    continue
                title = _get(row, col1, "Title")
                if not title:
                    sessions_skipped += 1
                    continue
                rec_id = hashlib.sha1(title.encode()).hexdigest()[:20]
                pdate = _get(row, col1, "Presentation Date")
                # datetime objects from openpyxl — format to string
                idx_pd = col1.get("Presentation Date")
                if idx_pd is not None and idx_pd < len(row) and row[idx_pd] is not None:
                    v = row[idx_pd]
                    if hasattr(v, "strftime"):
                        pdate = v.strftime("%Y-%m-%d")
                try:
                    await _hx(
                        "INSERT INTO SPARK_CRM_SESSIONS "
                        "(id, title, description, solution_area, target_audience, regions, language, "
                        "solution_advisor, advisor_email, agenda_created, invite_created, "
                        "presentation_date, crm_id, wrike_request, ptt_id, link_registro, imported_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            rec_id,
                            title[:512],
                            _get(row, col1, "Description"),
                            _get(row, col1, "Solution Area")[:128] or None,
                            _get(row, col1, "Target Audience")[:256] or None,
                            _get(row, col1, "Region(s)")[:256] or None,
                            _get(row, col1, "Language")[:16] or None,
                            _get(row, col1, "Solution Advisor")[:256] or None,
                            _get(row, col1, "Advisor Email")[:256] or None,
                            _get(row, col1, "Agenda Created")[:8] or None,
                            _get(row, col1, "Invite Created")[:8] or None,
                            pdate[:32] if pdate else None,
                            _get(row, col1, "CRM ID")[:128] or None,
                            _get(row, col1, "Wrike Request")[:128] or None,
                            _get(row, col1, "PTT ID")[:128] or None,
                            _get(row, col1, "Link de registro") or None,
                            now_ts,
                        )
                    )
                    sessions_imported += 1
                except Exception as e:
                    if _hana_is_dup(e):
                        sessions_dup += 1
                    else:
                        raise

    # ── LEADS sheet ───────────────────────────────────────────────────────────
    ws_leads = None
    for name in wb.sheetnames:
        if name.strip().upper() == "LEADS":
            ws_leads = wb[name]
            break

    if ws_leads:
        rows_l = list(ws_leads.iter_rows(values_only=True))
        header_idx = 0
        headers_l = []
        for i, row in enumerate(rows_l):
            cells = [str(c).strip() if c is not None else "" for c in row]
            if any(h in cells for h in ("Sesión", "Fecha", "CRM ID", "Empresa")):
                header_idx = i
                headers_l = cells
                break
        if headers_l:
            col_l = {h: i for i, h in enumerate(headers_l)}
            await _ensure_crm_leads_table()
            for row in rows_l[header_idx + 1:]:
                if all(v is None for v in row):
                    continue
                crm_id  = _get(row, col_l, "CRM ID")
                lead_id = _get(row, col_l, "Lead ID")
                empresa = _get(row, col_l, "Empresa")
                sesion  = _get(row, col_l, "Sesión")
                if not crm_id and not lead_id and not empresa:
                    leads_skipped += 1
                    continue
                row_key = crm_id or lead_id or empresa
                rec_id = hashlib.sha1(f"{sesion}_{row_key}".encode()).hexdigest()[:20]
                try:
                    await _hx(
                        "INSERT INTO SPARK_CRM_LEADS "
                        "(id, fecha, sesion, empresa, notas, producto, account_id, crm_id, lead_id, mu, pais, lob, sales_qualifier, status, imported_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            rec_id,
                            _get(row, col_l, "Fecha"),
                            sesion,
                            empresa,
                            _get(row, col_l, "Notas"),
                            _get(row, col_l, "Producto"),
                            _get(row, col_l, "Account ID"),
                            crm_id,
                            lead_id,
                            _get(row, col_l, "MU"),
                            _get(row, col_l, "País"),
                            _get(row, col_l, "LoB"),
                            _get(row, col_l, "Sales Qualifier"),
                            _get(row, col_l, "Status"),
                            now_ts,
                        )
                    )
                    leads_imported += 1
                except Exception as e:
                    if _hana_is_dup(e):
                        leads_dup += 1
                    else:
                        raise

    return {
        "ok": True,
        "sessions": {"imported": sessions_imported, "duplicate": sessions_dup, "skipped": sessions_skipped},
        "leads":    {"imported": leads_imported,    "duplicate": leads_dup,    "skipped": leads_skipped},
    }

@app.get("/api/crm-sessions")
async def list_crm_sessions(
    request: Request,
    title: str = Query(default=""),
    crm_id: str = Query(default=""),
    area: str = Query(default=""),
):
    _check_api_key(request)
    await _ensure_crm_sessions_table()
    clauses = []
    params  = []
    if title:
        clauses.append("LOWER(title) LIKE ?")
        params.append(f"%{title.lower()}%")
    if crm_id:
        clauses.append("LOWER(crm_id) LIKE ?")
        params.append(f"%{crm_id.lower()}%")
    if area:
        clauses.append("LOWER(solution_area) LIKE ?")
        params.append(f"%{area.lower()}%")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = await _hq(
        f"SELECT id, title, solution_area, target_audience, regions, language, "
        f"solution_advisor, advisor_email, agenda_created, invite_created, "
        f"presentation_date, crm_id, wrike_request, ptt_id, link_registro "
        f"FROM SPARK_CRM_SESSIONS {where} ORDER BY presentation_date DESC",
        tuple(params)
    )
    return rows

@app.delete("/api/crm-sessions")
async def clear_crm_sessions(request: Request):
    _check_api_key(request)
    await _ensure_crm_sessions_table()
    await _hx("DELETE FROM SPARK_CRM_SESSIONS")
    return {"ok": True}

@app.get("/api/crm-leads")
async def list_crm_leads(
    request: Request,
    sesion: str = Query(default=""),
    crm_id: str = Query(default=""),
    status: str = Query(default=""),
    empresa: str = Query(default=""),
):
    _check_api_key(request)
    await _ensure_crm_leads_table()
    clauses = []
    params  = []
    if sesion:
        clauses.append("LOWER(sesion) LIKE ?")
        params.append(f"%{sesion.lower()}%")
    if crm_id:
        clauses.append("LOWER(crm_id) LIKE ?")
        params.append(f"%{crm_id.lower()}%")
    if status:
        clauses.append("LOWER(status) LIKE ?")
        params.append(f"%{status.lower()}%")
    if empresa:
        clauses.append("LOWER(empresa) LIKE ?")
        params.append(f"%{empresa.lower()}%")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = await _hq(
        f"SELECT id, fecha, sesion, empresa, notas, producto, account_id, crm_id, lead_id, "
        f"mu, pais, lob, sales_qualifier, status, imported_at "
        f"FROM SPARK_CRM_LEADS {where} ORDER BY imported_at DESC",
        tuple(params)
    )
    return rows

@app.delete("/api/crm-leads")
async def clear_crm_leads(request: Request):
    _check_api_key(request)
    await _ensure_crm_leads_table()
    await _hx("DELETE FROM SPARK_CRM_LEADS")
    return {"ok": True}

# ── Pipeline ──────────────────────────────────────────────────────────────────

_PIPELINE_COLS = [
    ("opportunity_id",              "VARCHAR(64) PRIMARY KEY"),
    ("region_lvl1",                 "VARCHAR(128)"),
    ("region_lvl2",                 "VARCHAR(128)"),
    ("region_lvl3",                 "VARCHAR(128)"),
    ("region_lvl4",                 "VARCHAR(256)"),
    ("account_name",                "NVARCHAR(512)"),
    ("opp_description",             "NCLOB"),
    ("opp_owner_name",              "NVARCHAR(256)"),
    ("phase_since_days",            "VARCHAR(32)"),
    ("fc_qualification",            "VARCHAR(64)"),
    ("opp_phase",                   "VARCHAR(64)"),
    ("closing_qtr",                 "VARCHAR(16)"),
    ("deal_size_acv_eur",           "VARCHAR(64)"),
    ("closing_date",                "VARCHAR(32)"),
    ("age_days",                    "VARCHAR(32)"),
    ("phase_aging",                 "VARCHAR(64)"),
    ("phase_since_date",            "VARCHAR(32)"),
    ("untouched_days",              "VARCHAR(32)"),
    ("distribution_channel",        "VARCHAR(128)"),
    ("channel_manager",             "NVARCHAR(256)"),
    ("channel_partner",             "NVARCHAR(256)"),
    ("opp_campaign_text",           "NCLOB"),
    ("solution_area_l1",            "VARCHAR(128)"),
    ("sub_solution_area_l2",        "VARCHAR(128)"),
    ("solution_area_l3",            "VARCHAR(128)"),
    ("solution_area_l4",            "VARCHAR(128)"),
    ("drm_category",                "VARCHAR(64)"),
    ("iss_group_text",              "VARCHAR(128)"),
    ("sde_current_territory_owner", "NVARCHAR(256)"),
    ("pipe_build_type",             "VARCHAR(128)"),
    ("deal_qualification_decision", "VARCHAR(128)"),
    ("deal_qualification_score",    "VARCHAR(32)"),
    ("qualification_reviewer",      "NVARCHAR(256)"),
    ("qualification_date",          "VARCHAR(32)"),
    ("sde_handover_date",           "VARCHAR(32)"),
    ("local_acct_owner",            "NVARCHAR(256)"),
    ("account_planned_archetype",   "VARCHAR(256)"),
    ("ic_account_srg_text",         "VARCHAR(256)"),
    ("iac_engagement_model",        "VARCHAR(128)"),
    ("opp_origin",                  "VARCHAR(128)"),
    ("flsm_local_acct_owner",       "NVARCHAR(256)"),
    ("mm_pipe_source",              "VARCHAR(128)"),
    ("sde_initial_engagement_date", "VARCHAR(32)"),
    ("sde_initial_engagement_name", "NVARCHAR(256)"),
    ("sde_handover_name",           "NVARCHAR(256)"),
    ("sic_code",                    "VARCHAR(32)"),
    ("sic_description",             "NVARCHAR(256)"),
    ("sap_mastercode",              "VARCHAR(256)"),
    ("account_bp",                  "VARCHAR(64)"),
    ("opp_campaign_id",             "VARCHAR(128)"),
    ("source_file",                 "VARCHAR(256)"),
    ("imported_at",                 "VARCHAR(64)"),
]

# CSV column name → table column name (skipping empty columns at positions 14, 18, 36, 53, 54)
_CSV_TO_COL = {
    "Region Lvl 1":                       "region_lvl1",
    "Region Lvl 2":                       "region_lvl2",
    "Region Lvl 3":                       "region_lvl3",
    "Region Lvl 4":                       "region_lvl4",
    "Opportunity ID":                     "opportunity_id",
    "Account Name":                       "account_name",
    "Opp Description":                    "opp_description",
    "Opp Owner Name":                     "opp_owner_name",
    "Phase Since Days":                   "phase_since_days",
    "FC Qualification":                   "fc_qualification",
    "Opp Phase":                          "opp_phase",
    "Closing Qtr":                        "closing_qtr",
    "Deal Size(ACV EUR)":                 "deal_size_acv_eur",
    "Closing Date":                       "closing_date",
    "Age Days":                           "age_days",
    "Phase Aging":                        "phase_aging",
    "Phase Since Date":                   "phase_since_date",
    "Untouched Days":                     "untouched_days",
    "Distribution Channel":               "distribution_channel",
    "Channel Manager":                    "channel_manager",
    "Channel Partner":                    "channel_partner",
    "Opp Campaign Text":                  "opp_campaign_text",
    "Solution Area (L1)":                 "solution_area_l1",
    "Sub-Solution Area (L2)":             "sub_solution_area_l2",
    "Solution Area L3":                   "solution_area_l3",
    "Solution Area L4":                   "solution_area_l4",
    "DRM Category":                       "drm_category",
    "ISS Group Text":                     "iss_group_text",
    "SDE Current Territory Owner Name":   "sde_current_territory_owner",
    "Pipe Build Type Text":               "pipe_build_type",
    "Deal Qualification Decision":        "deal_qualification_decision",
    "Deal Qualification Score":           "deal_qualification_score",
    "Qualification Reviewer":             "qualification_reviewer",
    "Qualification Date":                 "qualification_date",
    "SDE Handover Date":                  "sde_handover_date",
    "Local Acct Owner":                   "local_acct_owner",
    "Account Planned Archetype Text":     "account_planned_archetype",
    "IC_ACCOUNT_SRG_TEXT":                "ic_account_srg_text",
    "IAC (Engagement Model)":             "iac_engagement_model",
    "Opp Origin":                         "opp_origin",
    "FLSM of Local Account Owner Name":   "flsm_local_acct_owner",
    "MM Pipe Source":                     "mm_pipe_source",
    "SDE Initial Engagement Date":        "sde_initial_engagement_date",
    "SDE Initial Engagement Name":        "sde_initial_engagement_name",
    "SDE Handover Name":                  "sde_handover_name",
    "SIC Code":                           "sic_code",
    "SIC Description":                    "sic_description",
    "SAP Mastercode":                     "sap_mastercode",
    "Account BP":                         "account_bp",
    "Opp Campaign ID":                    "opp_campaign_id",
}

_DATA_COLS = [c for c, _ in _PIPELINE_COLS]  # ordered list for INSERT

async def _ensure_pipeline_table():
    col_defs = ", ".join(f"{c} {t}" for c, t in _PIPELINE_COLS)
    try:
        await _hx(f"CREATE TABLE SPARK_PIPELINE ({col_defs})")
    except Exception as e:
        if not _hana_is_dup(e):
            raise

@app.post("/api/pipeline/import")
async def import_pipeline(request: Request, file: UploadFile = File(...)):
    _check_api_key(request)
    raw = await file.read()
    source_file = (file.filename or "unknown.csv")[:256]
    now_ts = datetime.now(timezone.utc).isoformat()

    text = raw.decode("utf-8-sig", errors="replace")
    del raw
    lines = text.splitlines()
    del text

    if len(lines) < 2:
        raise HTTPException(status_code=400, detail="CSV has fewer than 2 lines")

    # Line 0 = metadata, line 1 = actual headers (semicolon-delimited)
    headers = [h.strip() for h in lines[1].split(";")]
    csv_col_idx = {h: i for i, h in enumerate(headers)}

    def _val(row_cells: list, csv_name: str) -> str | None:
        i = csv_col_idx.get(csv_name)
        if i is None or i >= len(row_cells):
            return None
        v = row_cells[i].strip()
        return v if v and v != "(No Value)" else None

    await _ensure_pipeline_table()

    upsert_sql = (
        "UPSERT SPARK_PIPELINE (" + ", ".join(_DATA_COLS) + ") "
        "VALUES (" + ", ".join("?" * len(_DATA_COLS)) + ") WITH PRIMARY KEY"
    )

    _CHUNK = 500

    def _flush_chunk(rows: list) -> int:
        from spark_db import _new_conn, _adapt_sql, _adapt_params
        conn = _new_conn()
        try:
            cur = conn.cursor()
            adapted = _adapt_sql(upsert_sql)
            cur.executemany(adapted, [_adapt_params(r) for r in rows])
            conn.commit()
            return len(rows)
        finally:
            conn.close()

    chunk: list = []
    imported = 0
    skipped = 0

    for line in lines[2:]:
        if not line.strip():
            continue
        cells = line.split(";")
        opp_id = cells[csv_col_idx["Opportunity ID"]].strip() if "Opportunity ID" in csv_col_idx else ""
        if not opp_id:
            skipped += 1
            continue
        row_vals = {col: None for col in _DATA_COLS}
        for csv_name, db_col in _CSV_TO_COL.items():
            row_vals[db_col] = _val(cells, csv_name)
        row_vals["source_file"] = source_file
        row_vals["imported_at"] = now_ts
        chunk.append(tuple(row_vals[c] for c in _DATA_COLS))

        if len(chunk) >= _CHUNK:
            imported += await asyncio.to_thread(_flush_chunk, chunk)
            chunk = []

    if chunk:
        imported += await asyncio.to_thread(_flush_chunk, chunk)

    return {"ok": True, "imported": imported, "skipped": skipped, "source_file": source_file, "total_rows": imported + skipped}

@app.get("/api/pipeline/status")
async def pipeline_status(request: Request):
    _check_api_key(request)
    await _ensure_pipeline_table()
    rows = await _hq(
        "SELECT source_file, COUNT(*) AS cnt, MAX(imported_at) AS last_import "
        "FROM SPARK_PIPELINE GROUP BY source_file ORDER BY last_import DESC", ()
    )
    total = await _hq("SELECT COUNT(*) AS total FROM SPARK_PIPELINE", ())
    matched = await _hq(
        "SELECT COUNT(*) AS matched FROM SPARK_PIPELINE p "
        "WHERE EXISTS (SELECT 1 FROM SPARK_CRM_SESSIONS s WHERE p.opp_campaign_id = s.crm_id)", ()
    )
    return {
        "files": rows,
        "total": total[0]["total"] if total else 0,
        "matched": matched[0]["matched"] if matched else 0,
    }

@app.get("/api/pipeline/matched")
async def get_pipeline_matched(
    request: Request,
    account: str = Query(default=""),
    sde: str = Query(default=""),
    phase: str = Query(default=""),
    session: str = Query(default=""),
    area: str = Query(default=""),
):
    _check_api_key(request)
    await _ensure_pipeline_table()
    clauses = ["s.crm_id IS NOT NULL"]
    params  = []
    if account:
        clauses.append("LOWER(p.account_name) LIKE ?")
        params.append(f"%{account.lower()}%")
    if sde:
        clauses.append("LOWER(p.sde_current_territory_owner) LIKE ?")
        params.append(f"%{sde.lower()}%")
    if phase:
        clauses.append("LOWER(p.opp_phase) LIKE ?")
        params.append(f"%{phase.lower()}%")
    if session:
        clauses.append("LOWER(s.title) LIKE ?")
        params.append(f"%{session.lower()}%")
    if area:
        clauses.append("LOWER(p.solution_area_l1) LIKE ?")
        params.append(f"%{area.lower()}%")
    where = "WHERE " + " AND ".join(clauses)
    rows = await _hq(
        f"SELECT p.opportunity_id, p.account_name, p.opp_description, p.opp_owner_name, "
        f"p.opp_phase, p.fc_qualification, p.closing_qtr, p.deal_size_acv_eur, p.closing_date, "
        f"p.solution_area_l1, p.sub_solution_area_l2, p.drm_category, "
        f"p.sde_current_territory_owner, p.sde_initial_engagement_name, p.sde_handover_name, "
        f"p.sde_initial_engagement_date, p.sde_handover_date, "
        f"p.pipe_build_type, p.opp_origin, p.distribution_channel, "
        f"p.deal_qualification_decision, p.deal_qualification_score, "
        f"p.local_acct_owner, p.flsm_local_acct_owner, "
        f"p.opp_campaign_id, p.region_lvl1, p.region_lvl2, p.region_lvl3, "
        f"p.account_bp, p.source_file, "
        f"s.title AS session_title, s.solution_advisor AS session_advisor, "
        f"s.presentation_date AS session_date, s.regions AS session_regions "
        f"FROM SPARK_PIPELINE p "
        f"JOIN SPARK_CRM_SESSIONS s ON p.opp_campaign_id = s.crm_id "
        f"{where} "
        f"ORDER BY p.opp_phase, p.sde_current_territory_owner, p.account_name",
        tuple(params)
    )
    return rows

@app.delete("/api/pipeline")
async def clear_pipeline(request: Request):
    _check_api_key(request)
    await _ensure_pipeline_table()
    await _hx("DELETE FROM SPARK_PIPELINE")
    return {"ok": True}

app.mount("/", StaticFiles(directory=os.path.dirname(os.path.abspath(__file__)), html=True), name="static")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8768))
    uvicorn.run(app, host="0.0.0.0", port=port, reload=False)
