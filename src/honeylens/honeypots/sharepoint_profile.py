"""Response profile for the on-prem SharePoint decoy (see the SharePoint decoy proposal).

The header *shape* here is the one measured on a live on-prem SharePoint Subscription
Edition box (2026-10-06): ``Server: Microsoft-IIS/10.0``, ``X-Powered-By: ASP.NET``,
``MicrosoftSharePointTeamServices: 16.0.0.<build>`` (the **on-wire** form, build in the 4th
octet), ``X-Content-Type-Options: nosniff``, ``X-MS-InvokeApp``, a per-request
``SPRequestGuid``, and the NTLM / Bearer ``WWW-Authenticate`` challenges. Values that are
unique to a deployment (the tenant realm GUID, the request GUID) are generated per start /
per request, never shipped. A byte-for-byte corpus diff (as ``tests/test_netscaler_corpus_diff``
does for NetScaler) is a follow-up once the passive corpus under ``tests/data/sharepoint_corpus``
is captured — this module is the hand-built baseline until then.

Decision (docs/proposal §"Decided 2026-10-06"): the **exploit surfaces serve anonymously**
(200, not a 401 NTLM challenge) so the ToolShell chain proceeds and the MachineKey honeytoken
pays off. NTLM 401 stays only on background / non-exploit paths for partial realism.

The decoy never executes a payload, never serves a real MachineKey, never leaks memory.
"""

from __future__ import annotations

import secrets

from aiohttp import web

from honeylens.honeypots import deception_waf

# The constant, well-known SharePoint server principal (same on every tenant); only the realm
# GUID beside it is per-deployment. Used in the /_api Bearer challenge.
SHAREPOINT_PRINCIPAL = "00000003-0000-0ff1-ce00-000000000000"


def base_headers(build: str, *, request_guid: str, aspx: bool = False) -> dict[str, str]:
    """The identity header block a real on-prem SharePoint attaches to (almost) every response,
    in the order measured on a live SE box. ``Server`` is left to ``enforce_server_policy``;
    ``Date``/``Content-Length`` are aiohttp's. ``aspx`` adds the ASP.NET version header that the
    managed-handler surfaces (ToolPane, Picker, Home, _api) carry. ``build`` is the on-wire
    ``16.0.0.<build>`` form; ``request_guid`` is per-request; ``SPRequestDuration`` is a small
    varying value so it is not a static fingerprint."""
    h: dict[str, str] = {"X-SharePointHealthScore": "0"}
    if aspx:
        h["X-AspNet-Version"] = "4.0.30319"
    h["SPRequestGuid"] = request_guid
    h["request-id"] = request_guid
    h["X-FRAME-OPTIONS"] = "SAMEORIGIN"
    h["SPRequestDuration"] = str(secrets.randbelow(60) + 5)
    h["SPIisLatency"] = "0"
    h["X-Powered-By"] = "ASP.NET"
    h["MicrosoftSharePointTeamServices"] = build
    h["X-Content-Type-Options"] = "nosniff"
    h["X-MS-InvokeApp"] = "1; RequireReadOnly"
    return h


def redirect_home(build: str, *, request_guid: str, host: str) -> web.Response:
    """GET / on an anonymous-browsing site: 302 to the site's home page (measured behaviour).
    The Location host echoes the request Host, as the real box does."""
    headers = base_headers(build, request_guid=request_guid)
    headers["Location"] = f"http://{host}/SitePages/Home.aspx"
    headers["Content-Type"] = "text/html; charset=UTF-8"
    return web.Response(status=302, text="", headers=headers)


# Self-contained reproduction of the measured .181 classic team-site home (suite bar,
# top nav, Quick Launch, the "Get started with your site" tiles). The real page is a JS app
# that pulls corev15.css + ~10 /_layouts/15 scripts we cannot ship, so replaying its 97 KB
# HTML renders unstyled (the "looks like plain Apache" problem). This page inlines its own CSS
# and SVG so it renders as SharePoint everywhere, with no external requests and no lab data —
# the same approach as the NetScaler self-contained logon.
_HOME = """<!DOCTYPE html>
<html lang="en-US" dir="ltr">
<head>
<meta name="GENERATOR" content="Microsoft SharePoint"/>
<meta http-equiv="X-UA-Compatible" content="IE=10"/>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
<title>Home - Team Site</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:"Segoe UI","Segoe UI Web (West European)",Segoe,Tahoma,Helvetica,Arial,sans-serif;font-size:13px;color:#333;background:#fff}
a{color:#0072c6;text-decoration:none}a:hover{text-decoration:underline}
#suite{background:#000;color:#fff;height:30px;display:flex;align-items:center;padding:0 8px;font-size:13px}
#suite .waffle{width:30px;height:30px;display:flex;align-items:center;justify-content:center}
#suite .brand{font-weight:600;margin-left:2px}
#suite .right{margin-left:auto;display:flex;align-items:center;gap:16px}
#hdr{background:#fff;border-bottom:1px solid #edebe9;display:flex;align-items:center;padding:10px 16px;gap:12px}
#hdr .logo{width:30px;height:30px;background:#0072c6;border-radius:2px;color:#fff;font-weight:700;display:flex;align-items:center;justify-content:center}
#hdr .site{font-size:20px;font-weight:300}
#hdr .actions{margin-left:auto;display:flex;gap:18px;color:#767676;font-size:12px}
#nav{background:#f4f4f4;border-bottom:1px solid #edebe9;padding:0 16px;display:flex}
#nav a{padding:10px 14px;color:#444}
#nav a.sel{border-bottom:2px solid #0072c6;color:#0072c6;font-weight:600}
.layout{display:flex}
#ql{width:200px;padding:20px 10px;border-right:1px solid #f4f4f4}
#ql h3{font-size:11px;text-transform:uppercase;color:#767676;margin:0 0 6px 8px}
#ql a{display:block;padding:5px 8px;color:#333;border-radius:2px}
#ql a:hover{background:#f4f4f4}
#ql a.sel{font-weight:600;color:#0072c6}
#main{flex:1;padding:22px 28px}
#main h1{font-size:22px;font-weight:300;margin-bottom:2px}
#main .sub{color:#767676;margin-bottom:22px}
.gs{font-size:16px;font-weight:300;margin:0 0 12px}
.gs a{font-size:12px;margin-left:8px}
.tiles{display:grid;grid-template-columns:repeat(3,150px);gap:2px}
.tile{color:#fff;height:150px;padding:14px;display:flex;flex-direction:column;justify-content:space-between;background:#0072c6}
.tile:nth-child(2){background:#1a9ed9}.tile:nth-child(3){background:#2b88d8}
.tile:nth-child(4){background:#00a88e}.tile:nth-child(5){background:#5c2d91}.tile:nth-child(6){background:#e81123}
.tile .ic{font-size:28px}.tile .t{font-size:13px;font-weight:600;line-height:1.3}
</style>
</head>
<body>
<div id="suite">
<span class="waffle"><svg width="16" height="16" viewBox="0 0 16 16" fill="#fff" aria-hidden="true"><rect width="4" height="4"/><rect x="6" width="4" height="4"/><rect x="12" width="4" height="4"/><rect y="6" width="4" height="4"/><rect x="6" y="6" width="4" height="4"/><rect x="12" y="6" width="4" height="4"/><rect y="12" width="4" height="4"/><rect x="6" y="12" width="4" height="4"/><rect x="12" y="12" width="4" height="4"/></svg></span>
<span class="brand">SharePoint</span>
<span class="right"><span>&#9881;</span><span>?</span><span>System Account</span></span>
</div>
<div id="hdr">
<div class="logo">T</div>
<div class="site">Team Site</div>
<div class="actions"><span>&#128279; SHARE</span><span>&#9734; FOLLOW</span><span>&#9881;</span></div>
</div>
<div id="nav">
<a class="sel" href="/SitePages/Home.aspx">Home</a>
<a href="/Shared%20Documents/Forms/AllItems.aspx">Documents</a>
<a href="/_layouts/15/viewlsts.aspx">Site contents</a>
<a href="#">EDIT LINKS</a>
</div>
<div class="layout">
<div id="ql">
<a class="sel" href="/SitePages/Home.aspx">Home</a>
<a href="/Shared%20Documents/Forms/AllItems.aspx">Documents</a>
<a href="#">Recent</a>
<a href="/_layouts/15/viewlsts.aspx">Site contents</a>
<a href="#">EDIT LINKS</a>
</div>
<div id="main">
<h1>Home</h1>
<div class="sub">Welcome to the team site.</div>
<div class="gs">Get started with your site<a href="#">REMOVE THIS</a></div>
<div class="tiles">
<div class="tile"><span class="ic">&#128101;</span><span class="t">Share your site.</span></div>
<div class="tile"><span class="ic">&#128197;</span><span class="t">Working on a deadline?</span></div>
<div class="tile"><span class="ic">&#128193;</span><span class="t">Add lists, libraries, and other apps.</span></div>
<div class="tile"><span class="ic">&#127912;</span><span class="t">What&#39;s your style?</span></div>
<div class="tile"><span class="ic">&#128278;</span><span class="t">Your site. Your brand.</span></div>
<div class="tile"><span class="ic">&#9993;</span><span class="t">Keep email in context.</span></div>
</div>
</div>
</div>
</body>
</html>"""


def home_page(build: str, *, request_guid: str) -> web.Response:
    """GET /SitePages/Home.aspx — the anonymous home page (200)."""
    headers = base_headers(build, request_guid=request_guid, aspx=True)
    headers["Cache-Control"] = "private, max-age=0"
    headers["Content-Type"] = "text/html; charset=utf-8"
    return web.Response(status=200, text=_HOME, headers=headers)


def ntlm_challenge(build: str, *, request_guid: str) -> web.Response:
    """401 NTLM — the real box's answer on protected / non-anonymous paths (e.g. /_vti_*)."""
    headers = base_headers(build, request_guid=request_guid)
    headers["WWW-Authenticate"] = "NTLM"
    headers["Content-Type"] = "text/plain; charset=utf-8"
    return web.Response(status=401, text="401 UNAUTHORIZED", headers=headers)


def api_ntlm_challenge(build: str, *, request_guid: str) -> web.Response:
    """GET /_api/* with no bearer: measured as a 401 NTLM carrying the OData service headers
    (not a Bearer challenge — that only appears once a Bearer token is presented)."""
    headers = base_headers(build, request_guid=request_guid, aspx=True)
    headers["Cache-Control"] = "private, max-age=0"
    headers["X-SP-SERVERSTATE"] = "ReadOnly=0"
    headers["DATASERVICEVERSION"] = "3.0"
    headers["WWW-Authenticate"] = "NTLM"
    headers["Content-Type"] = "application/json;odata=verbose;charset=utf-8"
    return web.Response(status=401, text='{"error":"invalid_request"}', headers=headers)


def api_bearer_challenge(build: str, *, request_guid: str, realm: str) -> web.Response:
    """/_api with a Bearer token: the 401 leaks the auth realm. The realm GUID is
    per-deployment; the client_id and trusted_issuers principal are the constant well-known
    SharePoint values (the CVE-2023-29357 realm-probe surface)."""
    headers = base_headers(build, request_guid=request_guid, aspx=True)
    headers["Cache-Control"] = "private, max-age=0"
    headers["X-SP-SERVERSTATE"] = "ReadOnly=0"
    headers["DATASERVICEVERSION"] = "3.0"
    headers["WWW-Authenticate"] = (
        f'Bearer realm="{realm}",'
        f'client_id="{SHAREPOINT_PRINCIPAL}",'
        f'trusted_issuers="{SHAREPOINT_PRINCIPAL}@{realm}"'
    )
    headers["Content-Type"] = "application/json;odata=verbose;charset=utf-8"
    return web.Response(status=401, text='{"error":"invalid_request"}', headers=headers)


def service_cnf(build: str, *, request_guid: str) -> web.Response:
    """GET /_vti_pvt/service.cnf — the FrontPage version leak. ``vti_extenderversion`` carries
    the on-wire build so a scanner's version fingerprint matches the headers (measured body)."""
    headers = base_headers(build, request_guid=request_guid)
    headers["Content-Type"] = "application/octet-stream"
    body = f"vti_encoding:SR|utf8-nl\nvti_extenderversion:SR|{build}\n"
    return web.Response(status=200, text=body, headers=headers)


def _published_version(build: str) -> str:
    """Convert the on-wire build ``16.0.0.<build>`` to the published ``16.0.<build>.<rev>`` form
    the REST API reports in ``LibraryVersion``. Revision is absent in our profile, so it is 0 —
    the build number still agrees with the advertised identity."""
    parts = build.split(".")
    if len(parts) == 4 and parts[:3] == ["16", "0", "0"]:
        return f"16.0.{parts[3]}.0"
    return build


def start_page(build: str, *, request_guid: str) -> web.Response:
    """GET /_layouts/15/start.aspx — the modern SPA entry (B7). A real box serves a thin shell
    that bootstraps the single-page app; we serve a minimal 200 so the path is a live surface,
    not a 404 that marks the decoy."""
    headers = base_headers(build, request_guid=request_guid, aspx=True)
    headers["Cache-Control"] = "private, max-age=0"
    headers["Content-Type"] = "text/html; charset=utf-8"
    body = (
        "<!DOCTYPE html><html lang='en-US' dir='ltr'><head><title>Home</title>"
        "<meta name='GENERATOR' content='Microsoft SharePoint' /></head>"
        "<body><div id='s4-workspace'><div id='spPageCanvasContent'></div></div>"
        "<script type='text/javascript'>//<![CDATA[\nvar _spPageContextInfo = "
        "{ webAbsoluteUrl: '', siteAbsoluteUrl: '' };\n//]]></script></body></html>"
    )
    return web.Response(status=200, text=body, headers=headers)


def spdisco(build: str, *, request_guid: str) -> web.Response:
    """GET /_vti_bin/spdisco.aspx — the WS discovery document (B7). 200 text/xml with the
    ``<discovery>`` / ``<contractRef>`` elements a FrontPage/WS probe expects. Refs are relative
    so nothing host-specific or lab-specific ships."""
    headers = base_headers(build, request_guid=request_guid, aspx=True)
    headers["Cache-Control"] = "private, max-age=0"
    headers["Content-Type"] = "text/xml; charset=utf-8"
    body = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<discovery xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
        'xmlns="http://schemas.xmlsoap.org/disco/">'
        '<contractRef ref="/_vti_bin/sites.asmx?wsdl" docRef="/_vti_bin/sites.asmx" '
        'xmlns="http://schemas.xmlsoap.org/disco/scl/" />'
        '<contractRef ref="/_vti_bin/webs.asmx?wsdl" docRef="/_vti_bin/webs.asmx" '
        'xmlns="http://schemas.xmlsoap.org/disco/scl/" />'
        "</discovery>"
    )
    return web.Response(status=200, text=body, headers=headers)


def contextinfo(build: str, *, request_guid: str) -> web.Response:
    """POST /_api/contextinfo — the FormDigest/context endpoint (B6, CVE-2026-55040 surface).
    Returns the odata=verbose context JSON whose ``LibraryVersion`` agrees with the advertised
    build. The ``FormDigestValue`` is a fresh random token per request (never a reusable one)."""
    headers = base_headers(build, request_guid=request_guid, aspx=True)
    headers["Cache-Control"] = "private, max-age=0"
    headers["X-SP-SERVERSTATE"] = "ReadOnly=0"
    headers["DATASERVICEVERSION"] = "3.0"
    headers["Content-Type"] = "application/json;odata=verbose;charset=utf-8"
    digest = f"0x{secrets.token_hex(32).upper()}"
    library = _published_version(build)
    body = (
        '{"d":{"GetContextWebInformation":{'
        '"__metadata":{"type":"SP.ContextWebInformation"},'
        '"FormDigestTimeoutSeconds":1800,'
        f'"FormDigestValue":"{digest}",'
        f'"LibraryVersion":"{library}",'
        '"SiteFullUrl":"","SupportedSchemaVersions":{"__metadata":{"type":"Collection(Edm.String)"},'
        '"results":["14.0.0.0","15.0.0.0"]},"WebFullUrl":""}}}'
    )
    return web.Response(status=200, text=body, headers=headers)


def trust_signin_page(build: str, *, request_guid: str) -> web.Response:
    """GET /_trust/default.aspx — the WS-Federation sign-in landing. A real STS renders a
    token-POST form; the decoy serves a plausible one so a ``wa=wsignin1.0`` probe lands. It
    NEVER processes or deserialises a ``wresult`` (CVE-2026-50522) — a BinaryFormatter wresult
    is captured and tagged by the classifier, never executed."""
    headers = base_headers(build, request_guid=request_guid, aspx=True)
    headers["Cache-Control"] = "private, max-age=0"
    headers["Content-Type"] = "text/html; charset=utf-8"
    body = (
        "<!DOCTYPE html><html><head><title>Sign In</title></head>"
        "<body><form id='loginForm' method='post' action='/_trust/default.aspx'>"
        "<input type='hidden' name='wa' value='wsignin1.0'/>"
        "<input type='hidden' name='wctx' value='' />"
        "<input type='hidden' name='wresult' value='' />"
        "<h2>Sign in</h2></form></body></html>"
    )
    return web.Response(status=200, text=body, headers=headers)


# A minimal, dependency-free "ToolPane edit" surface. Real ToolPane.aspx in edit mode returns
# a web-part management page; we only need enough markers (ToolPane / MSOTlPn_ / web part) that
# a scanner's behavioural check scores the auth bypass as open. No Citrix/Microsoft assets are
# shipped; this is our own page, flagged as an intentional divergence for the future corpus diff.
_TOOLPANE_EDIT = (
    "<!DOCTYPE html><html><head><title>Edit Web Part Page</title></head>"
    '<body class="ms-dialog"><form id="MSOTlPn_Edit" method="post" action="/_layouts/15/ToolPane.aspx">'
    '<div id="MSOTlPn_ToolPane" class="ms-WPAddWebPart">Add Web Part</div>'
    '<input type="hidden" name="MSOTlPn_DWP" value="" />'
    '<input type="hidden" name="__VIEWSTATE" value="" />'
    "</form></body></html>"
)


def toolpane_edit(build: str, *, request_guid: str) -> web.Response:
    """200 edit surface for the ToolShell SignOut-Referer bypass. The request is captured and
    classified before this answers; this only makes the appliance read as exploitable."""
    headers = base_headers(build, request_guid=request_guid, aspx=True)
    headers["Cache-Control"] = "private, max-age=0"
    headers["Content-Type"] = "text/html; charset=utf-8"
    return web.Response(status=200, text=_TOOLPANE_EDIT, headers=headers)


_PICKER_FORM = (
    "<!DOCTYPE html><html><head><title>Select People and Groups</title></head>"
    '<body><form method="post" action="/_layouts/15/Picker.aspx">'
    '<span id="ctl00_PlaceHolderDialogBodySection_ctl05_hiddenSpanData"></span>'
    '<input type="hidden" name="__VIEWSTATE" value="" />'
    "</form></body></html>"
)


def picker_form(build: str, *, request_guid: str) -> web.Response:
    """200 people-picker form (CVE-2019-0604 surface). On an SE build this CVE is out of scope
    (SE postdates the 2019 fix) — the page is served as a recon surface only, never emulating
    the deserialization."""
    headers = base_headers(build, request_guid=request_guid, aspx=True)
    headers["Cache-Control"] = "private, max-age=0"
    headers["Content-Type"] = "text/html; charset=utf-8"
    return web.Response(status=200, text=_PICKER_FORM, headers=headers)


def spinstall0_dump(
    build: str, *, request_guid: str, validation_key: str, decryption_key: str
) -> web.Response:
    """The fake ``spinstall0.aspx`` crypto-dumper. ToolShell's whole point is to steal the
    ASP.NET MachineKey; this returns a **honeytoken** key (synthetic, per-deployment, never
    real) so a later ``__VIEWSTATE`` signed with it confirms the chain reached stage two.

    Intentional divergence from a clean box (which 404s / serves a SharePoint page for a
    non-existent aspx): this decoy answers as a box whose spinstall0 webshell is live, which
    is precisely the compromised state we want attackers to act on."""
    headers = base_headers(build, request_guid=request_guid, aspx=True)
    headers["Content-Type"] = "text/plain; charset=utf-8"
    # Exact ToolShell spinstall0 dump shape: pipe-delimited, 160 chars, NO trailing newline,
    # both keys 32 bytes (64 hex). The public backdoor template matches on len(body) <= 160, so
    # the old 291-char key=value form never tripped the "token taken" mechanism (A1).
    # CompatibilityMode=Framework20SP1 is the legacy MAC layout — HMACSHA256 over the ViewState
    # with NO modifier — which is exactly what honeypot_sharepoint._viewstate_signed_with_key
    # verifies, so an attacker who follows the advertised mode trips the honeytoken (A2).
    body = f"{validation_key}|HMACSHA256|{decryption_key}|Auto|Framework20SP1"
    return web.Response(status=200, text=body, headers=headers)


def error_500(build: str, *, request_guid: str) -> web.Response:
    """A SharePoint-flavoured 500 with a correlation id, as the server returns for a handled
    fault (e.g. a POST we accept but do not process). Correlation id == the request GUID."""
    headers = base_headers(build, request_guid=request_guid, aspx=True)
    headers["Content-Type"] = "text/html; charset=utf-8"
    body = (
        "<html><head><title>Error</title></head><body>"
        f"<p>Sorry, something went wrong.</p><p>Correlation ID: {request_guid}</p>"
        "</body></html>"
    )
    return web.Response(status=500, text=body, headers=headers)


def not_found(build: str, *, request_guid: str) -> web.Response:
    """IIS/SharePoint 404 for an unknown path (measured body: ``404 NOT FOUND``)."""
    headers = base_headers(build, request_guid=request_guid)
    headers["Content-Type"] = "text/html; charset=utf-8"
    return web.Response(status=404, text="404 NOT FOUND", headers=headers)


async def enforce_server_policy(request: web.Request, response: web.StreamResponse) -> None:
    """Force the IIS banner on every app response so ``Server`` never leaks Python/aiohttp,
    regardless of whether the import-time banner mask ran. The module mask still covers the
    400/413/431 aiohttp emits *before* the app runs, which this per-response hook cannot reach.
    Set (not setdefault): aiohttp has already written its own default by the time this runs.

    When the fake-vendor WAF canary is enabled (``config.WAF_CANARY_ENABLED``, off by
    default), also attach this sensor's WAF header to every response so the appliance
    identity is consistent across the whole decoy surface (a WAF that only fronted one page
    would itself be a tell). See ``honeypots/deception_waf.py``."""
    response.headers["Server"] = "Microsoft-IIS/10.0"
    # Fake-vendor WAF canary (off by default): one consistent appliance identity across all of
    # this sensor's web decoys. See honeypots/deception_waf.py.
    await deception_waf.on_response_prepare(request, response)
