# Fronting the decoy with an nginx edge

**What this is:** a reusable recipe for putting a single internet-facing host in
front of the NetScaler decoy so that the public IP and any domain you do *not*
serve land on the honeypot, while the real sites you host keep working. It is the
generalised form of a deployment that has run in production since 2026-10-02; the
site-specific instance (addresses, domains, VM layout) lives in the operator's
own infrastructure notes, not here.

The hard part is not the proxying. It is proxying **without leaving a proxy's
fingerprint**, because the whole value of the decoy is that it looks like a bare
NetScaler, not like something sitting behind nginx. Three details below decide
whether the masquerade holds; each one fails silently if you get it wrong.

## Topology

```
          Internet
             │
             ▼
   ┌───────────────────┐   :443  TCP stream (ssl_preread, no TLS termination)
   │   edge host        │────────────────────────────┐
   │   (public IP)      │   :80   HTTP reverse proxy  │
   │   nginx            │──────────────────┐          │
   └───────────────────┘                   │          │
             │ known site SNI              │          │
             ▼                             ▼          ▼
     real sites (127.0.0.1:8443)     decoy :50080   decoy :50443
                                     (HTTP)         (HTTPS, own cert)
```

The decoy runs on a separate host or VM reachable from the edge over a private
link. It binds the two ports the manifest assigns to the `netscaler` identity:

| Decoy host port | Maps to | Role |
|---|---|---|
| `50443` | container 443 | HTTPS surface, serves the decoy's **own** certificate |
| `50080` | container 80 | HTTP surface |

(`HONEYLENS_PORT_MAP=50443:443,50080:80` in the container environment — see
`honeylens.honeypots.manifest`.) Replace `DECOY_HOST` below with that host's
address on the private link.

## Decision 1 — port 443 goes through `stream`, never `proxy_pass`

The decoy serves its own certificate (a per-deployment Gateway hostname such as
`CN=sslvpn42`, not a fleet-wide fixed name) and its own TLS
fingerprint. If nginx terminated TLS on 443 and reverse-proxied cleartext to the
decoy, every attacker would see **nginx's** certificate and **nginx's** TLS
handshake. The disguise would collapse on the handshake, before a single HTTP
header could matter.

So 443 is handled at layer 4 by the `stream` module with `ssl_preread`: nginx
reads only the SNI out of the `ClientHello` and forwards the raw bytes
untouched. A connection to the bare IP carries **no SNI**, so
`$ssl_preread_server_name` is empty, the map sends it to `default`, and `default`
is the decoy. Any domain you do not explicitly list goes the same way.

```nginx
# stream.d/10-sni-routing.conf  —  included from a top-level `stream { }` block

map $ssl_preread_server_name $route_443 {
    example.org         sites;
    www.example.org     sites;
    default             decoy;      # bare IP (no SNI) and every unknown name
}

upstream sites {
    server 127.0.0.1:8443;          # the http{} block, see Decision 3
}

upstream decoy {
    server DECOY_HOST:50443;
}

# This is the ONLY place with real client attribution for 443 traffic: the
# http{} block downstream sees 127.0.0.1, never the real peer.
log_format sni443 '$remote_addr [$time_local] sni="$ssl_preread_server_name" '
                  '-> $upstream_addr $status $bytes_sent/$bytes_received $session_time';
access_log /var/log/nginx/stream-443.log sni443;

server {
    listen 443;
    listen [::]:443;
    ssl_preread on;
    proxy_pass $route_443;
    proxy_connect_timeout 5s;
    proxy_timeout 300s;
}
```

`stream` is a separate top-level block, a sibling of `http`, not something you
can put inside a `server`. On Debian/Ubuntu it needs `libnginx-mod-stream`
installed and loaded, with a version matching the nginx build.

## Decision 2 — on port 80, pass the upstream `Server` and `Date` headers

Port 80 has no SNI, so routing by name needs the HTTP layer; the edge proxies it
normally. The trap: **nginx hides the upstream `Server` and `Date` headers by
default and substitutes its own.** Without the two `proxy_pass_header` lines
below, the decoy's `Server: Apache` (or whatever banner it emits) silently
becomes `Server: nginx` — no error, nothing in the logs, masquerade gone.

```nginx
# conf.d/00-default.conf  —  the http{} default server for port 80

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    access_log /var/log/nginx/decoy-80.log;

    location / {
        proxy_pass http://DECOY_HOST:50080;
        proxy_http_version 1.1;

        proxy_set_header Host       $host;   # the decoy sees the name probed
        proxy_set_header Connection "";

        # Keep the decoy's own identity headers (see note above).
        proxy_pass_header Server;
        proxy_pass_header Date;

        proxy_redirect  off;                 # don't rewrite the decoy's Location
        proxy_buffering off;                 # deliver the response as it left

        proxy_connect_timeout 5s;
        proxy_read_timeout    120s;
    }
}
```

## Decision 3 — real client IP via the PROXY protocol, not `X-Forwarded-For`

The decoy's events should record the attacker, not the proxy. The reflexive fix,
`X-Forwarded-For` / `X-Real-IP`, is the wrong one here: it appends a header to the
**request** the decoy receives and leaves a trace of a proxy in front — the tell a
careful attacker looks for — and it cannot work on 443 anyway, because that path is
a raw TCP stream with no HTTP layer to carry a header.

The PROXY protocol solves both. The proxy prepends the real client address as a
short preamble on the connection, *below* TLS and below HTTP, so the attacker never
sees it; only the decoy reads it. It works identically on 443 (stream) and 80
(http).

On nginx, enable it toward the decoy upstream:

```nginx
# stream.d/10-sni-routing.conf — in the server { listen 443; ... } block
proxy_protocol on;                      # prepend the preamble to the upstream

# conf.d/00-default.conf — in the port-80 location that proxies to the decoy
location / {
    proxy_pass http://DECOY_HOST:50080;
    proxy_protocol on;
    # ... Host, proxy_pass_header Server/Date as in Decision 2 ...
}
```

The stream block proxies *both* the decoy and your real sites, so once it sends the
preamble the sites' `http{}` listener must accept it too, or their TLS handshake
breaks on the preamble bytes:

```nginx
listen 127.0.0.1:8443 ssl proxy_protocol;   # consume the preamble; keep real_ip as below
```

Keep the sites' `real_ip_header` as their CDN header (the stream's preamble carries
the CDN edge, not the end user); the `proxy_protocol` keyword there is only so the
TLS handshake survives.

The decoy must parse the preamble. This honeypot does, gated to trusted proxy
sources so a direct attacker cannot spoof an address: set
`HONEYLENS_PROXY_PROTOCOL` to the proxy's address (for example the bridge gateway
`10.0.0.1`, or a comma-separated list / CIDR; `1` trusts any source). A connection
from an untrusted peer is served as-is and its preamble, if any, is ignored.

**Order matters:** deploy the decoy with `HONEYLENS_PROXY_PROTOCOL` set *first* (it
stays correct with or without a preamble), then enable `proxy_protocol` on nginx. The
reverse order feeds raw preamble bytes to a decoy that is not expecting them.

You still keep the edge logs as a second record:

- `stream-443.log` — real TCP peer plus the SNI, for all 443 traffic;
- `decoy-80.log` — real peer for port 80.

(On a native DNAT deployment with no reverse proxy, the decoy already sees the real
source, so leave `HONEYLENS_PROXY_PROTOCOL` unset there.)

### Port 80 / plain HTTP: `HONEYLENS_HTTP_PROXY`

PROXY protocol covers the 443 stream. A front that reverse-proxies **HTTP** instead passes the
client in a header, and that needs its own setting: **`HONEYLENS_HTTP_PROXY`**, the address (or
comma-separated list / CIDR; `1` or `all` trusts any peer) of the proxy whose `X-Real-IP` the
decoy may believe.

The two are independent and you usually want both on a fronted decoy:

```
Environment=HONEYLENS_PROXY_PROTOCOL=10.0.0.1   # 443, stream, preamble
Environment=HONEYLENS_HTTP_PROXY=10.0.0.1       # 80, http, X-Real-IP
```

⚠️ **Set only the one your front actually speaks.** `HONEYLENS_PROXY_PROTOCOL` makes the listener
*expect* a preamble; pointing it at a front that does not send one breaks a working port. A front
that only reverse-proxies HTTP needs `HONEYLENS_HTTP_PROXY` alone.

**This failure is silent, and it does not look like a misconfiguration — it looks like lost
exposure.** With `HONEYLENS_HTTP_PROXY` unset the decoy records the **proxy's** address as the
source and ignores `X-Real-IP`, which is the correct safe default: honouring a client-supplied
header from an untrusted peer would let any attacker forge their own source address. But every
RFC1918 filter downstream — dashboards, actor analysis, threat reporting — then discards the
traffic as internal. A sensor can run like this for weeks and read as "external exposure lost"
until someone looks at the headers stored with the events.

Verify by asking whose address was recorded, not whether rows exist:

```sql
SELECT source, host(src_ip), count(*)
FROM sensor_events
WHERE timestamp > now() - interval '1 hour'
GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 10;
```

If one internal address dominates a fronted decoy, confirm it is really internal before trusting
any filter that excludes it — check a stored event's headers for `X-Real-IP`/`X-Forwarded-For`.
A private address is only evidence of a private *peer*, not of internal traffic.

## Side effect: your real sites now see 127.0.0.1

Once 443 is a raw stream, the `http{}` server for your sites is reached over
`127.0.0.1:8443`, so its access log shows `127.0.0.1` for every request. If the
sites sit behind a CDN that already sends the client IP in a header, restore it:

```nginx
# conf.d/10-sites.conf  (abridged — your real vhosts)

server {
    listen 127.0.0.1:8443 ssl;
    listen [::1]:8443 ssl;
    http2 on;
    server_name example.org www.example.org;

    # 443 arrives via the stream block, so the peer here is always 127.0.0.1.
    # Recover the real client from the CDN header the app already trusts.
    set_real_ip_from 127.0.0.1;
    set_real_ip_from ::1;
    real_ip_header   X-Client-IP;           # your CDN's client-IP header (e.g. CF-Connecting-IP for Cloudflare)

    ssl_certificate     /etc/nginx/ssl/sites.crt;
    ssl_certificate_key /etc/nginx/ssl/sites.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    # ... your normal proxy_pass to the site backend ...
}
```

## What port 80 still cannot hide

Port 443 is a byte-for-byte tunnel, so the decoy's response reaches the attacker
exactly as it left. Port 80 goes through nginx's HTTP engine, which makes small
changes a determined fingerprinter can see. Know them before you rely on the
port-80 path:

| | Decoy answering directly | Same response via the port-80 proxy |
|---|---|---|
| Header order | as the decoy emits it | nginx may reorder |
| `Connection` | absent | `keep-alive` added |
| `Server` on a redirect | **absent** (the decoy omits it on 3xx) | nginx injects `Server: nginx` |

The last row is the sharpest: the decoy deliberately sends **no** `Server` on its
entry redirect, but when the upstream omits a header nginx supplies its own, and
`proxy_pass_header` cannot pass a header that was never sent. Removing it needs
the third-party `headers-more` module (`more_clear_headers Server;`).

There is no free fix that keeps everything. Routing the **whole** of port 80 to
the decoy would erase these differences but also take away the `HTTP → HTTPS`
redirect and ACME challenges for your real sites. The pragmatic stance: treat 443
as the faithful surface and accept that port 80 is a slightly weaker disguise, or
add `headers-more` if port-80 realism matters for your threat model.

## Bring-up order and verification

1. **Open the public ports before you point DNS at the host.** An open port with
   no traffic is harmless; a changed DNS record pointing at a host that is not
   yet listening is downtime.
2. Install and load the stream module; add the `stream { include stream.d/*.conf; }`
   block to `nginx.conf`.
3. Move the real sites' TLS server to `127.0.0.1:8443` and add the `real_ip`
   restore.
4. `nginx -t`, then reload.

Checks that actually prove the disguise, not just that bytes flow:

```bash
# Bare IP (no SNI) must reach the decoy and show ITS certificate, not nginx's.
openssl s_client -connect PUBLIC_IP:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -subject          # expect the decoy's own Gateway CN (per-deployment)

# A known site name must still reach the real site.
curl -sI --resolve example.org:443:PUBLIC_IP https://example.org/ | head -n1

# The decoy's Server banner must survive the port-80 proxy.
curl -sI http://PUBLIC_IP/ | grep -i '^server:'    # expect the decoy's banner

# Attribution is on the edge, not in the decoy's request.
tail -f /var/log/nginx/stream-443.log              # real peer + SNI
```

A `curl` that returns `HTTP 000` against the HTTPS decoy is not necessarily
broken: a decoy configured as a tarpit completes the TLS handshake and then holds
the connection open on purpose.
