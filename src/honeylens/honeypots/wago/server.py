"""WAGO WBM-style HTTP deception surface."""

from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import logging
import re
from collections.abc import Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .detector import SourceTracker, classify
from .state import DeviceState

try:
    # Resolvable because hp_wago.py puts the package root on sys.path before it
    # imports this module. Optional so the decoy still runs outside the sensor tree.
    from honeylens.intelligence import ai_canary
except ImportError:  # canary is optional
    ai_canary = None  # type: ignore[assignment]  # optional module, idiom from the mypy docs

try:
    # Same arrangement as the canary above. `body_capture` is stdlib-only, so this adds
    # no dependency on the sensor's database or config layers.
    from honeylens.honeypots.body_capture import capture as _capture_body
except ImportError:  # pragma: no cover - standalone run outside the sensor tree
    _capture_body = None  # type: ignore[assignment]

# The event sink is duck-typed on purpose: this package must not import the sensor's
# database or config layers. hp_wago.py injects a sink that writes the HoneyLens log
# contract; the unit tests inject a list-backed stub.


NAV = [
    ("Information", "/wbm/state.php"),
    ("CODESYS", "/wbm/rts_info.php"),
    ("TCP/IP", "/wbm/tcpip.php"),
    ("Ethernet", "/wbm/ethernet.php"),
    ("NTP", "/wbm/sntp.ssi"),
    ("Clock", "/wbm/clock.ssi"),
    ("Users", "/wbm/users.ssi"),
    ("HMI Settings", "/wbm/hmi_settings.php"),
    ("Administration", "/wbm/administration.php"),
    ("Package Server", "/wbm/firmware_update.php"),
    ("Mass Storage", "/wbm/mass_storage.php"),
    ("Downloads", "/wbm/downloads.ssi"),
    ("Port", "/wbm/port.php"),
    ("Modbus", "/wbm/modbus.ssi"),
    ("SNMP", "/wbm/snmp.php"),
    ("I/O-Configuration", "/wbm/io_config.xml"),
    ("WebVisu", "/wbm/webvisu.php"),
]

MAX_BODY = 65536  # bytes read from any request body
MAX_SECRET = 256  # captured password bytes kept per attempt
# Form values are bounded, but the bound has to sit above the buffer-probe threshold
# in signatures.OVERLONG_PARAM — truncating at 512 made every oversized field report
# exactly 512 and understated a 3 KB probe as a borderline one.
MAX_FIELD = 4096

CSS = r"""
*{box-sizing:border-box}body{margin:0;background:#e8e8e8;color:#222;font:12px Arial,Helvetica,sans-serif}
#head{height:86px;background:linear-gradient(110deg,#17350e,#6ca92d);color:white;border-bottom:7px solid #a4c639;padding:16px 28px}
#head h1{margin:0;font-size:24px;font-weight:normal}.model{margin-top:8px;font-weight:bold}
#shell{display:grid;grid-template-columns:205px minmax(520px,920px);gap:18px;padding:18px;align-items:start}
#nav,.box,.status{background:#fff;border:1px solid #aaa;box-shadow:0 1px 2px #aaa}#nav h3,.status h3,.box caption{margin:0;background:#5f9728;color:#fff;text-align:left;padding:7px 9px;font-size:12px}
#nav ul{list-style:none;margin:0;padding:0}#nav a{display:block;padding:6px 10px;color:#153e0c;text-decoration:none;border-bottom:1px solid #ddd}#nav a:hover,#nav a.sel{background:#dfeecb;font-weight:bold}
#content h2{font-size:18px;font-weight:normal;color:#315d18;border-bottom:2px solid #78aa3b;padding-bottom:5px}.box{margin-bottom:13px;padding:0}.box table{width:100%;border-collapse:collapse}.box td,.box th{padding:7px 9px;border-bottom:1px solid #ddd;text-align:left}.box td:first-child{width:42%;color:#555}.box caption{caption-side:top}
.ok{color:#267d17;font-weight:bold}.warn{color:#bc6d00;font-weight:bold}.bad{color:#b32121;font-weight:bold}.button,button,input[type=submit]{border:1px solid #537d2d;background:#75a840;color:white;padding:5px 10px;cursor:pointer}.button:hover,button:hover,input[type=submit]:hover{background:#5c8d2e}input,select{padding:4px;border:1px solid #aaa}.notice{background:#fff8d7;border:1px solid #dbbd55;padding:8px;margin-bottom:12px}.footer{padding:10px 24px;color:#666;border-top:1px solid #bbb;background:#ddd}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.metric{background:#fff;border:1px solid #aaa;padding:12px}.metric b{display:block;font-size:24px;color:#3f751e;margin-top:5px}.bar{height:22px;background:#ddd;border:1px solid #999}.bar i{display:block;height:100%;background:#78ad3b}.alarm{background:#ffdede;border-color:#b32121}.controls{display:flex;gap:12px;align-items:center;flex-wrap:wrap}.mono{font-family:Consolas,monospace;font-size:11px}.small{font-size:10px;color:#666}@media(max-width:760px){#shell{grid-template-columns:1fr}#nav ul{columns:2}.grid{grid-template-columns:1fr 1fr}}
"""


def _e(value) -> str:
    return html.escape(str(value), quote=True)


def _nav(active: str) -> str:
    links = []
    for label, href in NAV:
        cls = ' class="sel"' if href == active else ""
        links.append(f'<li><a{cls} href="{href}">{_e(label)}</a></li>')
    return '<div id="nav"><h3>Navigation</h3><ul>{}</ul></div>'.format("".join(links))


def _page(state: DeviceState, active: str, title: str, content: str, notice: str = "") -> bytes:
    snap = state.snapshot()
    note = f'<div class="notice">{_e(notice)}</div>' if notice else ""
    document = """<!DOCTYPE html><html><head><meta charset="iso-8859-1">
<title>WAGO Ethernet Web-Based Management: {}</title><style>{}</style></head><body>
<div id="head"><h1>Web-Based Management</h1><div class="model">{}</div></div>
<div id="shell">{}<main id="content"><h2>{}</h2>{}{}</main></div>
<div class="footer">WAGO Kontakttechnik GmbH &amp; Co. KG &bull; Controller Services</div>
</body></html>""".format(
        _e(title), CSS, _e(snap["product"]), _nav(active), _e(title), note, content
    )
    return document.encode("iso-8859-1", "xmlcharrefreplace")


def _table(caption: str, rows: Sequence[tuple[str, object]]) -> str:
    body = "".join(f"<tr><td>{_e(k)}</td><td>{v}</td></tr>" for k, v in rows)
    return f'<div class="box"><table><caption>{_e(caption)}</caption>{body}</table></div>'


def _state_page(state: DeviceState) -> bytes:
    s = state.snapshot()
    status = (
        '<span class="ok">RUN</span>'
        if s["plc_state"] == "RUN"
        else '<span class="bad">STOP</span>'
    )
    content = _table(
        "Status",
        [
            ("WBM", '<span class="ok">OK</span>'),
            ("Local Time", _e(s["local_time"])),
            ("Local Date", _e(s["local_date"])),
            ("PLC Switch", status),
        ],
    )
    content += _table(
        "Controller Details",
        [
            ("Product Description", _e(s["product"])),
            ("Order Number", _e(s["order_number"])),
            ("License Information", _e(s["runtime_license"])),
            ("Firmware Revision", _e(s["firmware"])),
            ("Hostname", _e(s["hostname"])),
        ],
    )
    content += _table(
        "Network Details Eth0 (X1)",
        [
            ("State", '<span class="ok">enabled</span>'),
            ("MAC Address", _e(s["mac"])),
            ("IP Address", _e(s["ip_address"])),
            ("Subnet Mask", _e(s["netmask"])),
        ],
    )
    return _page(state, "/wbm/state.php", "Status Information", content)


def _runtime_page(state: DeviceState) -> bytes:
    s = state.snapshot()
    names = ["MainTask", "MAIN_Process", "TREND_TASK", "Main_IO", "Main_Time", "HttpTask"]
    intervals = [0, 20, 60000, 8, 1000, 8]
    rows = [("Number of tasks", str(len(names)))]
    for i, name in enumerate(names):
        rows.extend(
            [
                (f"Task {i}", f"<b>{_e(name)}</b>"),
                ("Cycle count", str(s["task_cycles"][i])),
                ("Cycletime (mcsec)", str(250 + i * 117)),
                ("Status", _e(s["plc_state"])),
                ("Mode", "CONTINUE"),
                ("Priority", str([255, 13, 15, 10, 14, 3][i])),
                ("Interval (msec)", str(intervals[i])),
            ]
        )
    content = _table(
        "Project Details",
        [
            ("Date", "2026-08-09-23:37:32"),
            ("Title", "Water Treatment Station"),
            ("Version", "2.4.7"),
            ("Author", "Automation Engineering"),
            ("Description", "Pump station control"),
        ],
    )
    content += _table(
        "CODESYS State", [("State", '<span class="ok">{}</span>'.format(_e(s["plc_state"])))]
    )
    content += _table("Tasks", rows)
    return _page(state, "/wbm/rts_info.php", "CODESYS Information", content)


def _webvisu(state: DeviceState, embedded: bool = False) -> bytes:
    s = state.snapshot()
    alarm_class = " alarm" if s["high_alarm"] or s["low_alarm"] else ""
    action = "/webvisu.htm" if not embedded else "/wbm/webvisu.php"
    content = """<div class="grid">
<div class="metric{}">Tank level<b id="level">{} %</b><div class="bar"><i style="width:{}%"></i></div></div>
<div class="metric">Temperature<b id="temp">{} &deg;C</b></div>
<div class="metric">Pressure<b id="pressure">{} bar</b></div>
<div class="metric">Flow<b id="flow">{} L/min</b></div></div>
<div class="box" style="margin-top:14px"><table><caption>Pump Station Control</caption><tr><td>PLC</td><td><b>{}</b></td></tr>
<tr><td>Pump P-101</td><td><b>{}</b></td></tr><tr><td>Automatic mode</td><td>{}</td></tr>
<tr><td colspan="2"><form method="post" action="{}" class="controls">
<input type="hidden" name="form-name" value="process_control">
<label>Pump <select name="pump"><option value="on"{}>ON</option><option value="off"{}>OFF</option></select></label>
<label>Mode <select name="automatic"><option value="on"{}>AUTO</option><option value="off"{}>MANUAL</option></select></label>
<label>Setpoint % <input type="number" min="0" max="100" step="0.1" name="setpoint" value="{}"></label>
<label>Outlet valve % <input type="number" min="0" max="100" step="0.1" name="valve" value="{}"></label>
<input type="submit" value="Apply"></form></td></tr></table></div>
<p class="small">Values refresh every two seconds. Controls update the simulated process image; Modbus service is provided separately by HoneyLens.</p>
<script>setTimeout(function(){{location.reload()}},2000)</script>""".format(
        alarm_class,
        s["tank_level"],
        s["tank_level"],
        s["temperature"],
        s["pressure"],
        s["flow"],
        _e(s["plc_state"]),
        "RUNNING" if s["pump"] else "STOPPED",
        "AUTO" if s["automatic"] else "MANUAL",
        action,
        " selected" if s["pump_command"] else "",
        "" if s["pump_command"] else " selected",
        " selected" if s["automatic"] else "",
        "" if s["automatic"] else " selected",
        s["setpoint"],
        s["valve"],
    )
    return _page(state, "/wbm/webvisu.php" if embedded else "", "PLC WebVisu", content)


def _validate_ipv4(value: str) -> str:
    return str(ipaddress.IPv4Address(value))


class WBMHandler(BaseHTTPRequestHandler):
    server: WBMServer
    server_version = "lighttpd"
    sys_version = ""
    # The captured device answers `HTTP/1.1 200 OK`; BaseHTTPRequestHandler defaults to
    # 1.0, and that mismatch is visible in the first line of every response.
    protocol_version = "HTTP/1.1"
    # Without this, a client that declares a large Content-Length and then sends
    # nothing parks a thread forever waiting for a body that never arrives — cheap
    # slowloris-style exhaustion of a ThreadingHTTPServer. socketserver applies this
    # to the connection, so a stalled read gives up instead of holding the worker.
    timeout = 5

    @property
    def state(self) -> DeviceState:
        return self.server.device_state

    @property
    def events(self):
        """Event sink injected by the server; see module note on duck typing."""
        return self.server.event_logger

    def log_message(self, fmt, *args):
        return

    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str = "text/html; charset=iso-8859-1",
        extra: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "PHP/5.2.9")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra:
            for key, value in extra.items():
                self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _redirect(self, location: str) -> None:
        self._send(302, b"", "text/plain", {"Location": location})

    def _peer(self) -> tuple[str, int]:
        return self.client_address[0], int(self.client_address[1])

    def _classify(
        self, method: str, path: str, fields: dict[str, str] | None = None, body: bytes = b""
    ) -> dict[str, object]:
        """Run the catalogue and the per-source tracker, and return the detection as
        event fields. Detection never changes what the attacker is served in this
        phase — a decoy that answers differently once it recognises an exploit is a
        decoy that can be probed for its own detection rules."""
        text = body.decode("utf-8", "replace") if body else ""
        detection = classify(method, path, fields or {}, text)
        tracker = getattr(self.server, "tracker", None)
        extra = tracker.observe(self.client_address[0], path, detection) if tracker else []
        indicators = list(detection.indicators) + extra

        out: dict[str, object] = {}
        if detection.matched:
            out["attack_type"] = detection.attack_type
            out["rule_name"] = detection.rule_name
            out["confidence"] = detection.confidence
            if detection.cve_id:
                out["cve"] = detection.cve_id
        elif extra:
            # No single-request shape, but the source's behaviour over time says
            # something: a page sweep is recon and worth typing on its own.
            out["attack_type"] = "WAGO_RECON"
            out["rule_name"] = "wago_wbm_enumeration"
        if indicators:
            out["indicators"] = indicators
        return out

    def _capture(self, path: str, raw: bytes) -> dict[str, object]:
        """The body as event fields, so it survives past this function.

        `_read_form` reads the whole declared body (up to MAX_BODY) and `_classify`
        looks at it — and until 2026-10-25 it was then dropped, leaving `content_length`
        and the parsed `fields` as the only trace. For a urlencoded login that is nearly
        lossless; for anything else it is not. Three PHP2Shell exploitation POSTs to this
        decoy on 2026-10-23 were stored as the 15 bytes `POST /index.php`, classified
        `WAGO_EXPLOIT_ATTEMPT` because the port was all the classifier had, and recovered
        only by cross-checking Suricata. `fields` was empty for them: the body was
        `multipart/form-data`, which `_read_form` does not parse.

        Bodies are kept verbatim, credentials included — see
        `honeylens.honeypots.body_capture`, which argues that case and puts redaction at
        publication rather than at capture.

        The firmware-upload endpoint is the one exception, and deliberately so: this
        decoy promises to discard uploads after hashing (module docstring, and the
        `stored: False` field on that event), and a 64 KiB slice of someone's dropper is
        exactly what that promise is about.
        """
        if _capture_body is None or path.startswith("/wbm/firmware_update.php"):
            return {}
        return dict(
            _capture_body(raw, path, self.headers.get("Content-Type", ""), max_capture=MAX_BODY)
        )

    def _read_form(self) -> tuple[dict[str, str], bytes]:
        try:
            declared = int(self.headers.get("Content-Length", "0") or 0)
        except (TypeError, ValueError):
            declared = 0  # junk header: read nothing, answer normally
        length = min(max(declared, 0), MAX_BODY)
        raw = self.rfile.read(length) if length else b""
        content_type = self.headers.get("Content-Type", "")
        fields: dict[str, str] = {}
        if content_type.startswith("application/x-www-form-urlencoded"):
            parsed = parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
            fields = {k: v[-1][:MAX_FIELD] for k, v in parsed.items()}
        return fields, raw

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        details: dict[str, Any] = {
            "method": "GET",
            "path": path,
            "query": parsed.query[:512],
            "user_agent": self.headers.get("User-Agent", "")[:256],
        }
        query_fields = {k: v[-1] for k, v in parse_qs(parsed.query).items()}
        details.update(self._classify("GET", path, query_fields))
        self.events.emit(
            "http",
            "http_request",
            self._peer(),
            "HIGH" if details.get("attack_type") else "INFO",
            details,
        )
        if path in ("/", "/index.html", "/wbm", "/wbm/", "/wbm/index.html"):
            return self._redirect("/wbm/state.php")
        if path in ("/wbm/state.php", "/wbm/state.php.html"):
            return self._send(200, _state_page(self.state))
        if path in ("/wbm/rts_info.php", "/wbm/rts_info.php.html"):
            return self._send(200, _runtime_page(self.state))
        if path in ("/webvisu.htm", "/webvisu.html"):
            return self._send(200, _webvisu(self.state))
        if path in ("/wbm/webvisu.php", "/wbm/webvisu.php.html"):
            return self._send(200, _webvisu(self.state, embedded=True))
        if path == "/api/state":
            body = json.dumps(self.state.snapshot(), separators=(",", ":")).encode()
            return self._send(200, body, "application/json; charset=utf-8")
        if path in ("/wbm/ajax_functions.php", "/wbm/ajax_functions.php.html"):
            return self._ajax(parse_qs(parsed.query))
        if path in ("/wbm/io_config.xml", "/wbm/io_config.xml.html"):
            body = self._io_xml().encode("iso-8859-1")
            return self._send(200, body, "application/xml; charset=iso-8859-1")
        if path == "/wbm/plc_backup.cfg":
            s = self.state.snapshot()
            body = (
                "# WAGO controller backup\nhostname={}\nmodbus_unit={}\nproject=WaterTreatment\n".format(
                    s["hostname"], s["unit_id"]
                )
            ).encode()
            self.events.emit(
                "http", "configuration_download", self._peer(), "MEDIUM", {"file": "plc_backup.cfg"}
            )
            extra = {"Content-Disposition": "attachment; filename=plc_backup.cfg"}
            # A controller backup is a configuration artefact, so it earns a canary
            # (Idea 52) for the same reason a FortiGate admin session does: an agent
            # that reads it and follows what it finds identifies itself as an agent.
            # The whole surface stays byte-identical for everyone else — the bait is
            # header-only, so no fetched file differs from a real controller's.
            if (
                ai_canary is not None
                and ai_canary.enabled()
                and ai_canary.carrier_enabled("WAGO_CONFIG_BACKUP")
            ):
                _nonce, _canary_headers = ai_canary.issue(
                    "wago",
                    "/wbm/plc_backup.cfg",
                    self.headers.get("Host", ""),
                    origin_src_ip=self._peer()[0],
                    context="WAGO controller backup",
                )
                extra.update(_canary_headers)
            return self._send(200, body, "application/octet-stream", extra)
        return self._generic_page(path)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        fields, raw = self._read_form()
        safe_fields = {k: v for k, v in fields.items() if "pass" not in k.lower()}
        details: dict[str, Any] = {
            "method": "POST",
            "path": path,
            "content_type": self.headers.get("Content-Type", "")[:128],
            "content_length": len(raw),
            "fields": safe_fields,
        }
        details.update(self._capture(path, raw))
        details.update(self._classify("POST", path, fields, raw))
        self.events.emit(
            "http",
            "http_request",
            self._peer(),
            "HIGH" if details.get("attack_type") else "INFO",
            details,
        )
        try:
            if path in ("/wbm/ajax_functions.php", "/wbm/ajax_functions.php.html"):
                return self._ajax({k: [v] for k, v in fields.items()})
            if path in (
                "/webvisu.htm",
                "/webvisu.html",
                "/wbm/webvisu.php",
                "/wbm/webvisu.php.html",
            ):
                self._process_control(fields)
                return self._send(200, _webvisu(self.state, path.startswith("/wbm/")))
            if path in ("/wbm/administration.php", "/wbm/administration.php.html"):
                action = fields.get("plc-action", "").lower()
                if action in ("run", "stop"):
                    self.state.set_plc_state(action)
                elif action == "reset":
                    self.state.reset()
                # Only a real command is a command. This page also carries account
                # administration, and emitting `wbm_action` for every POST to it
                # reported user creation as "PLC state command" — on a plant that is
                # the difference between someone adding an account and someone
                # stopping the controller. Anything else here is left to the request
                # classifier, which names what it actually saw.
                if action:
                    self.events.emit(
                        "http",
                        "wbm_action",
                        self._peer(),
                        "CRITICAL" if action in ("stop", "reset") else "HIGH",
                        {"action": "plc_" + action, "path": path, "method": "POST"},
                    )
                return self._generic_page(path, "Controller command accepted")
            if path in ("/wbm/tcpip.php", "/wbm/tcpip.php.html"):
                hostname = (
                    re.sub(r"[^A-Za-z0-9_.-]", "", fields.get("hostname", ""))[:63]
                    or self.state.hostname
                )
                ip = _validate_ipv4(fields.get("ip-address", self.state.ip_address))
                mask = _validate_ipv4(fields.get("subnet-mask", self.state.netmask))
                gateway = _validate_ipv4(fields.get("gateway", self.state.gateway))
                self.state.update_network(hostname, ip, mask, gateway)
                self.events.emit(
                    "http",
                    "network_configuration_attempt",
                    self._peer(),
                    "HIGH",
                    {"hostname": hostname, "ip": ip, "netmask": mask, "gateway": gateway},
                )
                return self._generic_page(
                    path, "Configuration saved. Changes take effect after reset."
                )
            if path in ("/wbm/users.ssi", "/wbm/users.ssi.html"):
                username = fields.get("username", "")[:64]
                password = fields.get("password", "")[:MAX_SECRET]
                self.events.emit(
                    "http",
                    "credential_attempt",
                    self._peer(),
                    "HIGH",
                    {
                        "username": username,
                        "password": password,
                        "password_length": len(fields.get("password", "")),
                        "password_sha256_prefix": hashlib.sha256(
                            fields.get("password", "").encode("utf-8", "replace")
                        ).hexdigest()[:16],
                    },
                )
                return self._generic_page(path, "Authentication failed")
            if path in ("/wbm/firmware_update.php", "/wbm/firmware_update.php.html"):
                # The body is capped at MAX_BODY, so this is not the digest of the
                # upload — naming it `sha256` would mislead anyone correlating samples.
                self.events.emit(
                    "http",
                    "firmware_upload_attempt",
                    self._peer(),
                    "CRITICAL",
                    {
                        "content_length": len(raw),
                        "declared_length": self.headers.get("Content-Length", ""),
                        f"sha256_first_{MAX_BODY // 1024}k": hashlib.sha256(raw).hexdigest(),
                        "truncated": len(raw) >= MAX_BODY,
                        "stored": False,
                    },
                )
                return self._generic_page(path, "Package validation failed: invalid signature")
            if path in ("/wbm/hmi_settings.php", "/wbm/hmi_settings.php.html"):
                if "display-state" in fields:
                    self.state.display_on = fields["display-state"] == "on"
                if "cleanmode-state" in fields:
                    self.state.cleanmode = fields["cleanmode-state"] == "on"
                self.events.emit("http", "hmi_configuration", self._peer(), "MEDIUM", safe_fields)
                return self._generic_page(path, "HMI setting applied")
            if path in ("/wbm/modbus.ssi", "/wbm/modbus.ssi.html"):
                enabled = fields.get("enabled", "on") == "on"
                unit = max(1, min(247, int(fields.get("unit-id", self.state.unit_id))))
                self.state.modbus_enabled, self.state.unit_id = enabled, unit
                self.events.emit(
                    "http",
                    "modbus_configuration",
                    self._peer(),
                    "HIGH",
                    {"enabled": enabled, "unit_id": unit},
                )
                return self._generic_page(path, "Modbus setting applied")
        except (ValueError, TypeError) as exc:
            self.events.emit(
                "http",
                "invalid_configuration",
                self._peer(),
                "MEDIUM",
                {"path": path, "error": str(exc)[:160]},
            )
            return self._send(
                400, _page(self.state, path, "Invalid Configuration", "<p>Invalid value.</p>")
            )
        return self._generic_page(path, "Request accepted")

    def _process_control(self, fields: dict[str, str]) -> None:
        pump = fields.get("pump", "off") == "on"
        automatic = fields.get("automatic", "off") == "on"
        setpoint = max(0.0, min(100.0, float(fields.get("setpoint", "65"))))
        valve = max(0.0, min(100.0, float(fields.get("valve", "25"))))
        self.state.write_coils(2, [automatic])
        self.state.write_coils(0, [pump])
        self.state.write_registers(0, [round(setpoint * 10), round(valve * 10)])
        self.events.emit(
            "http",
            "webvisu_control",
            self._peer(),
            "HIGH",
            {
                "pump": pump,
                "automatic": automatic,
                "setpoint": setpoint,
                "valve": valve,
            },
        )

    def _ajax(self, params: dict[str, list[str]]) -> None:
        function = (params.get("function_name") or [""])[-1]
        s = self.state.snapshot()
        if function == "get_display_state":
            result = {"displayState": "on" if s["display_on"] else "off"}
        elif function == "get_cleanmode_state":
            result = {"cleanmodeState": "on" if s["cleanmode"] else "off"}
        elif function == "restart_webserver":
            self.events.emit(
                "http", "webserver_restart_attempt", self._peer(), "HIGH", {"simulated": True}
            )
            result = {"status": "ok", "restart": "scheduled"}
        else:
            result = {"status": "error", "message": "unknown function"}
        self._send(200, json.dumps(result).encode(), "application/json; charset=utf-8")

    def _generic_page(self, path: str, notice: str = "") -> None:
        s = self.state.snapshot()
        route = path[:-5] if path.endswith(".html") else path
        title = dict((href, label) for label, href in NAV).get(route, "Not Found")
        if title == "Not Found":
            return self._send(
                404, _page(self.state, "", title, "<p>The requested resource was not found.</p>")
            )
        if route == "/wbm/tcpip.php":
            content = _table(
                "TCP/IP Configuration",
                [
                    ("Hostname", '<input name="hostname" value="{}">'.format(_e(s["hostname"]))),
                    (
                        "IP Address",
                        '<input name="ip-address" value="{}">'.format(_e(s["ip_address"])),
                    ),
                    (
                        "Subnet Mask",
                        '<input name="subnet-mask" value="{}">'.format(_e(s["netmask"])),
                    ),
                    ("Gateway", '<input name="gateway" value="{}">'.format(_e(s["gateway"]))),
                ],
            )
            content = f'<form method="post" action="/wbm/tcpip.php">{content}<input type="submit" value="SUBMIT"></form>'
        elif route == "/wbm/ethernet.php":
            content = _table(
                "Ethernet Interface X1",
                [
                    ("State", '<span class="ok">enabled</span>'),
                    ("Speed", "100 Mbit/s"),
                    ("Duplex", "full"),
                    ("MAC Address", _e(s["mac"])),
                    ("Received packets", str(s["rx_packets_base"] + s["runtime_seconds"] * 2)),
                    ("Transmitted packets", str(s["tx_packets_base"] + s["runtime_seconds"])),
                ],
            )
        elif route == "/wbm/sntp.ssi":
            content = _table(
                "NTP Configuration",
                [
                    ("State", '<span class="ok">enabled</span>'),
                    ("Primary server", _e(s["ntp_server"])),
                    ("Refresh interval", "3600 sec"),
                    ("Last sync", _e(s["local_time"])),
                ],
            )
        elif route == "/wbm/clock.ssi":
            content = _table(
                "Controller Clock",
                [
                    ("Date", _e(s["local_date"])),
                    ("Time", _e(s["local_time"])),
                    ("Timezone", "Europe/Warsaw"),
                    ("RTC state", '<span class="ok">synchronised</span>'),
                ],
            )
        elif route == "/wbm/users.ssi":
            content = _table(
                "User Management",
                [("Configured users", "admin, user"), ("Authentication", "local")],
            )
            content += '<div class="box"><table><caption>Login Test</caption><tr><td colspan="2"><form method="post" action="/wbm/users.ssi"><input name="username" placeholder="User"> <input type="password" name="password" placeholder="Password"> <input type="submit" value="LOGIN"></form></td></tr></table></div>'
        elif route == "/wbm/hmi_settings.php":
            content = _table(
                "Display",
                [
                    ("Actual state", "on" if s["display_on"] else "off"),
                    ("Cleanmode", "on" if s["cleanmode"] else "off"),
                    ("Screensaver", "enabled"),
                    ("Wait time", "300 sec"),
                ],
            )
            content += '<form method="post" action="/wbm/hmi_settings.php"><select name="display-state"><option>on</option><option>off</option></select> <select name="cleanmode-state"><option>off</option><option>on</option></select> <input type="submit" value="Apply"></form>'
        elif route == "/wbm/administration.php":
            content = _table(
                "Controller State",
                [
                    ("PLC", "<b>{}</b>".format(_e(s["plc_state"]))),
                    ("Reset counter", str(s["reset_count"])),
                    ("Configuration generation", str(s["config_generation"])),
                ],
            )
            content += '<form method="post" action="/wbm/administration.php" class="controls"><button name="plc-action" value="run">RUN</button><button name="plc-action" value="stop">STOP</button><button name="plc-action" value="reset">RESET</button></form>'
        elif route == "/wbm/firmware_update.php":
            content = _table(
                "Installed Package",
                [
                    ("Firmware", _e(s["firmware"])),
                    ("Package status", '<span class="ok">valid</span>'),
                ],
            )
            content += '<form method="post" enctype="multipart/form-data" action="/wbm/firmware_update.php"><input type="file" name="package"> <input type="submit" value="INSTALL"></form>'
        elif route == "/wbm/mass_storage.php":
            content = _table(
                "Internal Flash",
                [
                    ("Total", "512 MB"),
                    ("Used", "148 MB"),
                    ("Available", "364 MB"),
                    ("State", '<span class="ok">mounted read/write</span>'),
                ],
            )
        elif route == "/wbm/downloads.ssi":
            content = _table(
                "Downloads",
                [
                    ("Configuration backup", '<a href="/wbm/plc_backup.cfg">plc_backup.cfg</a>'),
                    ("System log", '<a href="/wbm/system.log">system.log</a>'),
                ],
            )
        elif route == "/wbm/port.php":
            content = _table(
                "Service Ports",
                [
                    ("WBM", "8081/TCP enabled"),
                    ("WebVisu", "8080/TCP enabled"),
                    ("Modbus TCP", "502/TCP enabled" if s["modbus_enabled"] else "disabled"),
                    ("CODESYS", "2455/TCP enabled"),
                    ("SSH", "22/TCP disabled"),
                ],
            )
        elif route == "/wbm/modbus.ssi":
            content = _table(
                "Modbus TCP",
                [
                    ("State", "enabled" if s["modbus_enabled"] else "disabled"),
                    ("Unit ID", str(s["unit_id"])),
                    ("Connections", "8"),
                    ("Watchdog", "1000 ms"),
                ],
            )
            content += '<form method="post" action="/wbm/modbus.ssi"><select name="enabled"><option value="on">enabled</option><option value="off">disabled</option></select> Unit ID <input name="unit-id" type="number" min="1" max="247" value="{}"> <input type="submit" value="Apply"></form>'.format(
                s["unit_id"]
            )
        elif route == "/wbm/snmp.php":
            content = _table(
                "SNMP",
                [
                    ("State", "enabled" if s["snmp_enabled"] else "disabled"),
                    ("Version", "SNMP v1/v2c"),
                    ("System name", _e(s["hostname"])),
                    ("Location", _e(s["snmp_location"])),
                ],
            )
        elif route == "/wbm/webvisu.php":
            return self._send(200, _webvisu(self.state, embedded=True))
        else:
            content = "<p>Service available.</p>"
        return self._send(200, _page(self.state, route, title, content, notice))

    def _io_xml(self) -> str:
        s = self.state.snapshot()
        inputs = [
            int(s["temperature"] * 10),
            int(s["tank_level"] * 10),
            int(s["pressure"] * 100),
            int(s["flow"] * 10),
        ]
        channels = "".join(
            f'<Channel name="AI{i + 1}" address="IW{i}" value="0x{value & 0xFFFF:04X}" />'
            for i, value in enumerate(inputs)
        )
        return """<?xml version="1.0" encoding="iso-8859-1"?>
<WAGO><Controller order="750-8202" firmware="{}" state="{}" />
<Module position="1" article="750-430" type="DI" channels="8" />
<Module position="2" article="750-530" type="DO" channels="8" />
<Module position="3" article="750-455" type="AI" channels="4">{}</Module>
<Module position="4" article="750-550" type="AO" channels="2" />
<EndModule position="5" article="750-600" /></WAGO>""".format(
            _e(s["firmware"]),
            _e(s["plc_state"]),
            channels,
        )


class WBMServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        """Scanners abandon connections constantly; socketserver's default dumps a
        full traceback per event, which would bury the journal on an exposed sensor.
        The decoy's own event log already records what arrived."""
        logging.getLogger("wago_honeypot").debug("connection error from %s", client_address)

    def __init__(self, address, state: DeviceState, logger):
        self.device_state = state
        self.event_logger = logger
        self.tracker = SourceTracker()
        super().__init__(address, WBMHandler)
