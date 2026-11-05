#!/usr/bin/env python3
"""
Push ESS session cookies to the running Spark Meeting server.

Modes:
  --auto          Extract cookies directly from Chrome (no manual copy needed)
  --auto --safari Extract cookies from Safari instead of Chrome
  --serve         Start local HTTP daemon on port 7788 (for UI button integration)
  status          Check current cookie status on the server
  <file>          Read cookie string from a file
  (no args)       Prompt for manual cookie paste

Usage examples:
  python3 ess_cookie_push.py --auto
  python3 ess_cookie_push.py --auto --safari
  python3 ess_cookie_push.py status
  python3 ess_cookie_push.py cookies.txt
"""

import json
import ssl
import sys
import urllib.request

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

APP_URL = "https://spark-meeting.cfapps.us10-002.hana.ondemand.com"
API_KEY = "2026DigtalSparkMeeting@!#"
ESS_DOMAIN = "ess.int.sap"


def parse_cookie_string(raw: str) -> dict:
    cookies = {}
    for part in raw.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            cookies[k.strip()] = v.strip()
    return cookies


def push_cookies(cookies: dict) -> None:
    payload = json.dumps({"cookies": cookies}).encode()
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["X-API-Key"] = API_KEY
    req = urllib.request.Request(
        f"{APP_URL}/api/ess/cookies",
        data=payload,
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15, context=_SSL_CTX) as resp:
        result = json.loads(resp.read())
    print(f"OK — {result.get('cookie_count', '?')} cookies pushed at {result.get('updated_at', '?')}")


def check_status() -> None:
    headers = {}
    if API_KEY:
        headers["X-API-Key"] = API_KEY
    req = urllib.request.Request(f"{APP_URL}/api/ess/status", headers=headers)
    with urllib.request.urlopen(req, timeout=10, context=_SSL_CTX) as resp:
        result = json.loads(resp.read())
    print(f"Status: {result.get('cookie_count', 0)} cookies | last update: {result.get('updated_at') or 'nunca'}")
    print(f"Templates configurados: {result.get('templates_configured', [])}")


def extract_from_browser(use_safari: bool = False) -> dict:
    try:
        import browser_cookie3
    except ImportError:
        print("ERROR: browser_cookie3 not installed.")
        print("Run:  pip3 install browser-cookie3")
        sys.exit(1)

    print(f"Extracting cookies from {'Safari' if use_safari else 'Chrome'} for {ESS_DOMAIN}...")

    try:
        if use_safari:
            jar = browser_cookie3.safari(domain_name=ESS_DOMAIN)
        else:
            jar = browser_cookie3.chrome(domain_name=ESS_DOMAIN)
    except Exception as e:
        print(f"ERROR reading browser cookies: {e}")
        print()
        if not use_safari:
            print("Make sure Chrome is not open with the cookie database locked, or try --safari.")
        sys.exit(1)

    cookies = {}
    for c in jar:
        if ESS_DOMAIN in c.domain or c.domain.endswith(".sap"):
            cookies[c.name] = c.value

    if not cookies:
        print(f"No cookies found for {ESS_DOMAIN}.")
        print("Make sure you are logged into ESS in your browser before running --auto.")
        sys.exit(1)

    print(f"Found {len(cookies)} cookies.")
    return cookies


if __name__ == "__main__":
    args = sys.argv[1:]

    if "--serve" in args:
        from http.server import HTTPServer, BaseHTTPRequestHandler

        PORT = 7788
        use_safari = "--safari" in args

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path not in ("/refresh", "/refresh?"):
                    self._html(404, "✗", "Not found")
                    return
                try:
                    cookies = extract_from_browser(use_safari)
                    push_cookies(cookies)
                    self._html(200, "✓", f"{len(cookies)} cookies atualizados")
                except Exception as exc:
                    self._html(500, "✗", str(exc))

            def _html(self, code, icon, msg):
                color = "#2B7D2B" if code == 200 else "#c0392b"
                close_js = "setTimeout(()=>window.close(),1800);" if code == 200 else ""
                body = f"""<!DOCTYPE html><html><head><meta charset=UTF-8>
<style>body{{margin:0;font-family:Arial,sans-serif;display:flex;align-items:center;
justify-content:center;height:100vh;background:#f5f6f7}}
.box{{text-align:center;padding:32px 40px;border-radius:12px;background:#fff;
box-shadow:0 2px 16px rgba(0,0,0,.12)}}</style></head>
<body><div class=box>
<div style="font-size:48px">{icon}</div>
<div style="color:{color};font-size:15px;margin-top:12px;font-weight:600">{msg}</div>
<div style="font-size:12px;color:#999;margin-top:10px">ESS · Spark Meeting</div>
<script>{close_js}</script>
</div></body></html>""".encode()
                self.send_response(code)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        print(f"ESS daemon pronto em http://localhost:{PORT}/refresh")
        print("Mantenha aberto enquanto usa o Spark Meeting. Ctrl+C para parar.")
        HTTPServer(("localhost", PORT), _Handler).serve_forever()
        sys.exit(0)

    if "status" in args:
        check_status()
        sys.exit(0)

    if "--auto" in args:
        use_safari = "--safari" in args
        cookies = extract_from_browser(use_safari)
        print(f"Pushing {len(cookies)} cookies...")
        try:
            push_cookies(cookies)
        except Exception as e:
            print(f"ERRO: {e}")
            sys.exit(1)
        sys.exit(0)

    # File mode
    if args and not args[0].startswith("--"):
        cookie_file = args[0]
        with open(cookie_file, "r") as f:
            raw = f.read().strip()
        print(f"Lendo cookies de {cookie_file}...")
    else:
        # Manual paste mode
        print("Spark Meeting — ESS Cookie Push")
        print("=" * 40)
        print("Cole o cookie string abaixo e pressione Enter duas vezes (linha em branco para finalizar):\n")
        lines = []
        while True:
            try:
                line = input()
            except EOFError:
                break
            if line == "" and lines:
                break
            lines.append(line)
        raw = "".join(lines).strip()

    if not raw:
        print("Cancelado — nenhum cookie fornecido.")
        sys.exit(1)
    cookies = parse_cookie_string(raw)
    print(f"Parsed {len(cookies)} cookies, enviando...")
    try:
        push_cookies(cookies)
    except Exception as e:
        print(f"ERRO: {e}")
        sys.exit(1)
