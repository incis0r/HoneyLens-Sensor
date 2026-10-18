"""Measured ``classic_gateway`` response profile for the NetScaler decoy.

A byte-for-byte replay of a real on-prem NetScaler Gateway running the classic LogonPoint
theme, captured passively into ``tests/data/netscaler_corpus`` and shipped here as package
data. The classic theme is the stock Citrix page served identically by thousands of
appliances — it carries no victim branding — so the decoy presents a generic, convincing
Gateway instead of a hand-guessed one. ``tests/test_netscaler_corpus_diff.py`` pins every
response value (status, header values, Set-Cookie order, body sha256) to the reference.

Header realism that matters (and that the earlier hand-written set got wrong):

* **Server is per-surface, not global.** The Gateway sends *no* ``Server`` on redirects and
  ``Server: Apache`` on content and 404s — never a single ``Microsoft-IIS`` on everything.
* **HSTS is the measured ``max-age=123456789``** on this appliance (no includeSubDomains,
  no preload) — not a textbook value.
* **Cookies ride the flow, not every GET.** The entry redirect emits seven *clearing*
  ``NSC_*`` cookies in a fixed order; the logon page sets none.
* **No ``Citrix-TransactionId`` on the Gateway logon surface.** That header belongs to
  StoreFront, a different profile.
"""

from __future__ import annotations

from importlib import resources

from aiohttp import web

from honeylens.honeypots import deception_waf

# The measured classic-gateway HSTS value (this appliance; deliberately not a textbook one).
HSTS = "max-age=123456789"
LOGON_PATH = "/logon/LogonPoint/tmindex.html"

# Seven clearing cookies in the exact measured order (duplicate names are intentional). Only
# the names/order are part of the contract; the values are a 1970-expiry clearing pattern.
_CLEAR_COOKIES = (
    "NSC_DLGE",
    "NSC_USER",
    "NSC_CERT",
    "NSC_TEMP",
    "NSC_PERS",
    "NSC_TEMP",
    "NSC_PERS",
)
_EXPIRED = "Thu, 01-Jan-1970 00:00:10 GMT"


def _load(name: str) -> bytes:
    return (
        resources.files("honeylens.honeypots")
        .joinpath("netscaler_profiles", "classic_gateway", name)
        .read_bytes()
    )


_ROOT_REDIRECT = _load("root_redirect.body")
_NOT_FOUND = _load("not_found.html")

# The logon surface is a self-contained page. The measured
# classic LogonPoint is a JavaScript single-page app: it pulls jQuery and ~8 more libraries from
# receiver/js/external/ and only then do ctxs.core/webui build the UI. We cannot ship those stock
# Citrix libraries or the theme images, so replaying the measured HTML renders a broken page in a
# browser. Instead the decoy serves its own dependency-free NetScaler Gateway logon: inline CSS,
# an inline SVG mark, no external requests — it renders identically everywhere. The entry
# redirect, the Apache 404 and all headers stay byte-for-byte as measured; only this page is ours.
# tests/test_netscaler_corpus_diff.py marks the logon scenarios as an intentional divergence.
_LOGON_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<meta name="robots" content="none"/>
<title>NetScaler Gateway</title>
<link rel="icon" href="data:image/svg+xml,\
%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E\
%3Crect width='32' height='32' rx='6' fill='%23122a45'/%3E\
%3Cpath d='M9 20V12l7 5 7-5v8' fill='none' stroke='%234aa3df' stroke-width='2.4' \
stroke-linejoin='round' stroke-linecap='round'/%3E%3C/svg%3E"/>
<style>
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{font-family:"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#1d2b3a;
background:radial-gradient(circle at 50% -20%,#1b3e63 0%,#102841 45%,#0a1b2e 100%)}
.wrap{min-height:100%;display:flex;align-items:center;justify-content:center;padding:24px}
.card{width:100%;max-width:400px;background:#fff;border-radius:10px;
box-shadow:0 18px 50px rgba(0,0,0,.45);padding:40px 36px 30px;animation:rise .4s ease}
@keyframes rise{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
.brand{display:flex;align-items:center;gap:12px;margin-bottom:28px}
.brand svg{flex:0 0 auto}
.brand .t{line-height:1.1}
.brand .t b{display:block;font-size:19px;font-weight:600;color:#122a45}
.brand .t span{font-size:12px;color:#6b7a8d;letter-spacing:.3px}
h1{font-size:15px;font-weight:600;margin:0 0 18px;color:#33465c}
label{display:block;font-size:12.5px;color:#55657a;margin:0 0 5px}
.field{margin-bottom:18px}
input[type=text],input[type=password]{width:100%;height:42px;padding:0 13px;font-size:14px;
border:1px solid #cdd6e0;border-radius:6px;background:#fbfcfe;color:#1d2b3a;transition:border .15s,box-shadow .15s}
input:focus{outline:none;border-color:#2b7fc2;box-shadow:0 0 0 3px rgba(43,127,194,.18)}
button{width:100%;height:44px;border:0;border-radius:6px;font-size:14.5px;font-weight:600;
color:#fff;background:linear-gradient(#2b86c8,#1f6fab);cursor:pointer;transition:filter .15s}
button:hover{filter:brightness(1.06)}
.err{background:#fbe9e7;border:1px solid #f1b7b0;color:#9c2a1e;font-size:12.5px;
border-radius:6px;padding:10px 12px;margin-bottom:18px}
.foot{margin:26px 0 0;font-size:11px;color:#8a97a6;text-align:center;line-height:1.5}
</style>
</head>
<body>
<div class="wrap">
<main class="card" role="main">
<div class="brand">
<svg width="40" height="40" viewBox="0 0 32 32" aria-hidden="true">
<rect width="32" height="32" rx="6" fill="#122a45"/>
<path d="M9 20V12l7 5 7-5v8" fill="none" stroke="#4aa3df" stroke-width="2.4"
stroke-linejoin="round" stroke-linecap="round"/>
</svg>
<div class="t"><b>NetScaler Gateway</b><span>Citrix Systems, Inc.</span></div>
</div>
<h1>Please log on</h1>
{error_block}
<form method="post" action="/cgi/login" autocomplete="off" spellcheck="false">
<div class="field"><label for="login">User name</label>
<input type="text" id="login" name="login" autocapitalize="off" autocorrect="off"/></div>
<div class="field"><label for="passwd">Password</label>
<input type="password" id="passwd" name="passwd"/></div>
<button type="submit">Log On</button>
</form>
<p class="foot">Access to this system is for authorized users only.<br/>
&copy; Citrix Systems, Inc. All rights reserved.</p>
</main>
</div>
</body>
</html>
"""

_LOGON = _LOGON_PAGE.replace("{error_block}", "").encode("utf-8")
_FAILED_LOGIN = _LOGON_PAGE.replace(
    "{error_block}",
    '<div class="err" role="alert">Incorrect user name or password. '
    "Type your user name and password again and click Log On.</div>",
).encode("utf-8")

# Shared security/identity headers for the logon surface (as a real Gateway sends them).
_LOGON_HEADERS = {
    "Server": "Apache",
    "X-Frame-Options": "SAMEORIGIN",
    "Feature-Policy": "camera 'none'; microphone 'none'; geolocation 'none'",
    "Referrer-Policy": "no-referrer",
    "X-XSS-Protection": "1; mode=block",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Content-Type": "text/html; charset=utf-8",
    "Strict-Transport-Security": HSTS,
}


def redirect() -> web.Response:
    """Entry redirect (GET / and GET /vpn/index.html): 302 to the LogonPoint, no Server,
    seven clearing NSC_* cookies in order, Connection: close."""
    resp = web.Response(
        status=302,
        body=_ROOT_REDIRECT,
        headers={
            "Location": LOGON_PATH,
            "Strict-Transport-Security": HSTS,
            "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1; mode=block",
            "Cache-control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Content-Type": "text/html; charset=utf-8",
        },
    )
    for name in _CLEAR_COOKIES:
        resp.headers.add("Set-Cookie", f"{name}=; expires={_EXPIRED}; path=/; secure; HttpOnly")
    resp.force_close()  # Connection: close, as measured
    return resp


def logon_page() -> web.Response:
    """The self-contained NetScaler Gateway logon page. No Set-Cookie and no
    Citrix-TransactionId on this surface; aiohttp drops the body for HEAD, keeps Content-Length."""
    return web.Response(status=200, body=_LOGON, headers=dict(_LOGON_HEADERS))


def failed_login() -> web.Response:
    """Login POST response: 200 re-rendering the logon page with the classic Gateway error
    banner. The request (credentials, injection markers) is already captured before this runs."""
    return web.Response(status=200, body=_FAILED_LOGIN, headers=dict(_LOGON_HEADERS))


def not_found() -> web.Response:
    """Apache 404 (48 bytes, iso-8859-1). No cache headers, no Citrix-TransactionId."""
    return web.Response(
        status=404,
        body=_NOT_FOUND,
        headers={
            "Server": "Apache",
            "X-Frame-Options": "SAMEORIGIN",
            "Content-Type": "text/html; charset=iso-8859-1",
            "Strict-Transport-Security": HSTS,
        },
    )


async def enforce_server_policy(request: web.Request, response: web.StreamResponse) -> None:
    """Server-header policy for the whole app: absent on redirects, Apache otherwise. aiohttp
    has already applied its default (masked to Apache) by the time this runs, so a redirect
    must actively drop it. This replaces the old global Microsoft-IIS banner.

    Also attaches this sensor's fake-vendor WAF canary header (off by default) so the appliance
    presents one consistent WAF across every decoy surface. See honeypots/deception_waf.py."""
    if 300 <= response.status < 400:
        response.headers.pop("Server", None)
    else:
        response.headers.setdefault("Server", "Apache")
    await deception_waf.on_response_prepare(request, response)
