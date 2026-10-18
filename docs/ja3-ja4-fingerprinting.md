> **Ported from the 0.9 documentation set, 2026-10-12.** Adapted for the 1.0 line: code lives in the `honeylens` package under `src/honeylens/`. Line/entry counts are from the origin document — re-check against current source. No client or infrastructure identifiers. Note: sensor-1.0 ships under **AGPL-3.0**, so the FoxIO License 1.1 section below is directly relevant to redistribution.

# JA3 / JA4+ TLS Fingerprinting Implementation

## Overview

HoneyLens implements a dual TLS fingerprinting system for identifying applications, libraries,
and malware from their network handshake behavior. Every TLS connection to any honeypot port
is fingerprinted, stored in PostgreSQL, and looked up against a 276K+ fingerprint database
for application identification.

| System | Standard | Author | What it fingerprints |
|--------|----------|--------|---------------------|
| **JA3** | MD5 of ClientHello components | Salesforce | TLS client (cipher suites, extensions, curves) |
| **JA3S** | MD5 of ServerHello components | Salesforce | TLS server response |
| **JA4** | SHA256 of sorted ClientHello | FoxIO | TLS client (human-readable + hash) |
| **JA4S** | Server response fingerprint | FoxIO | TLS server response |
| **JA4H** | HTTP client fingerprint | FoxIO | HTTP headers, cookies, methods |
| **JA4X** | Certificate fingerprint | FoxIO | X.509 issuer, subject, extensions |
| **JA4T** | TCP fingerprint | FoxIO | TCP window, options, TTL |

---

## How JA3 Works

**File:** `src/honeylens/classification/ja3.py` (516 lines)

JA3 creates an MD5 hash from 5 fields extracted from the TLS ClientHello message:

```
JA3 = MD5( SSLVersion, CipherSuites, Extensions, EllipticCurves, ECPointFormats )
```

### Extraction process

1. **Parse TLS record layer** — identify ContentType 0x16 (Handshake), then HandshakeType 0x01 (ClientHello)
2. **Extract fields:**
   - SSL/TLS version (e.g., 0x0303 = TLS 1.2)
   - Cipher suites — list of supported ciphers, comma-separated decimal
   - Extensions — list of extension type IDs, comma-separated decimal
   - Elliptic curves (Supported Groups) — from extension 0x000a
   - EC point formats — from extension 0x000b
3. **Filter GREASE values** — RFC 8701 values (0x0a0a, 0x1a1a, ..., 0xfafa) are removed.
   Browsers randomize these to prevent fingerprint ossification, so they must be stripped
   for consistent hashing.
4. **Join with commas**, hash with MD5

### Example

```
Raw:   771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-22-23-13-43-45-51-21,29-23-30-25-24,0-1-2
JA3:   e7d705a3286e19ea42f587b344ee6865
Match: Chrome on Windows
```

### JA3S (server fingerprint)

Same concept for ServerHello, using: `MD5(SSLVersion, CipherSuite, Extensions)`
(singular cipher suite — server picks one).

### Known fingerprint database

112 hardcoded entries in `ja3.py` covering:
- Browsers: Chrome, Firefox, Safari, Edge, Opera (multiple versions)
- Malware: Trickbot, Emotet, Dridex, Metasploit, CobaltStrike
- Scanners: Nmap, Zgrab, Masscan, Censys
- Libraries: Python requests, Go net/http, Java, curl

---

## How JA4+ Works

**File:** `src/honeylens/classification/ja4.py` (800+ lines)

JA4 improves on JA3 with a three-part format that is both human-readable AND hashable:

```
JA4 = a_b_c

a = human-readable metadata (protocol, version, SNI, counts, ALPN)
b = truncated SHA256 of sorted cipher suites (12 hex chars)
c = truncated SHA256 of sorted extensions + signature algorithms (12 hex chars)
```

### Part 'a' decoding

```
Position:  0    1-2   3    4-5   6-7   8-9
Meaning:   proto vers  SNI  ciph  ext   ALPN
Example:   t    13    d    15    16    h2
           TCP  1.3   domain 21ciphers 22ext HTTP/2
```

- Protocol: `t` = TCP, `q` = QUIC, `d` = DTLS
- Version: `13` = TLS 1.3, `12` = TLS 1.2, `11` = TLS 1.1, `10` = TLS 1.0
- SNI: `d` = domain present, `i` = IP or no SNI
- Cipher/Extension counts: 2-digit hex
- ALPN: `h2` = HTTP/2, `h1` = HTTP/1.1, `h3` = HTTP/3, `00` = none

### Key difference from JA3: sorting

JA4 **sorts** cipher suites and extensions before hashing. JA3 preserves order.
This means JA4 is more stable across implementations that randomize ordering
(like Chrome's TLS 1.3 cipher suite shuffling), but loses ordering information
that could distinguish otherwise-identical clients.

### JA4S (Server Response)

```
Format: protocol + version + ext_count + "00" _ cipher_hex _ ext_hash
Example: t130200_1301_a56c5b993250
```

### JA4H (HTTP Client)

```
Format: method + version + cookie_flag + referer_flag + header_count + language
        _ header_hash _ cookie_hash _ cookie_value_hash
Example: ge11cn020000_9ed1ff1f7b03_cd8dafe26982
```

Fingerprints the HTTP client based on header ordering, cookie presence, and
language preferences — useful for identifying HTTP-based C2 and malware droppers.

### JA4X (X.509 Certificate)

```
Format: issuer_hash _ subject_hash _ extension_hash
```

Each component is SHA256 of DER-encoded fields, truncated to 12 chars.
Identifies certificates by their structural properties regardless of the actual
values (domain, dates, etc.).

### JA4T (TCP)

```
Format: window_size _ ttl _ mss _ options
Example: 1024_2_1460_00
```

Fingerprints the TCP stack itself — window size, TTL, MSS, and TCP options
can identify operating systems and network tools.

### Known fingerprint database

163 hardcoded entries in `ja4.py` spanning all JA4 types, including:
- IcedID malware (JA4, JA4S, JA4H)
- SocGholish loader
- AsyncRAT
- Common browsers and libraries

---

## Database Architecture

### Event fingerprints: `ja4_fingerprints` table

Stores fingerprints extracted from live traffic:

```sql
CREATE TABLE ja4_fingerprints (
    id              BIGSERIAL PRIMARY KEY,
    event_id        VARCHAR(64) REFERENCES sensor_events(event_id),
    fingerprint_type VARCHAR(16),    -- 'ja4', 'ja4s', 'ja4h', 'ja4x', 'ja4t'
    fingerprint     VARCHAR(128),    -- Full fingerprint (a_b_c)
    fingerprint_a   VARCHAR(32),     -- Human-readable part
    fingerprint_b   VARCHAR(16),     -- First hash
    fingerprint_c   VARCHAR(16),     -- Second hash
    fingerprint_raw TEXT,            -- Unsorted components
    tls_version     VARCHAR(16),
    sni             VARCHAR(255),
    alpn            VARCHAR(64),
    cipher_count    INTEGER,
    extension_count INTEGER,
    identified      VARCHAR(128),    -- Matched application name
    metadata        JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
```

8 indexes for fast lookups by fingerprint, type, SNI, time range.

### Reference database: `ja4_database` table

Imported from FoxIO's official `ja4+_db.json` (208MB, 36K+ entries → 276K+ fingerprints
after expanding all fingerprint types per entry):

```sql
CREATE TABLE ja4_database (
    fingerprint         TEXT NOT NULL,
    fingerprint_type    VARCHAR(20),     -- JA4, JA4S, JA4H, JA4T, JA4X, JA4TS, JA4TSCAN
    application         VARCHAR(255),    -- Chrome, Firefox, Nmap, CobaltStrike, etc.
    library             VARCHAR(255),    -- OpenSSL, BoringSSL, etc.
    device              VARCHAR(255),
    os                  VARCHAR(255),
    verified            BOOLEAN,
    UNIQUE(fingerprint, fingerprint_type)
);
```

### Attacker fingerprints: `attacker_fingerprints` table

Aggregates fingerprints per attacker IP across events:

```sql
INSERT INTO attacker_fingerprints
    (ip, fingerprint_type, fingerprint_value, fingerprint_hash, detail,
     event_count, first_seen, last_seen)
ON CONFLICT (ip, fingerprint_type, fingerprint_hash) DO UPDATE SET
    event_count = event_count + 1,
    last_seen = NOW()
```

---

## Data Flow

```
Incoming TLS connection (any honeypot port)
    │
    ├──► eBPF captures raw packet data
    │
    ▼
classification/ja3.py
    parse_client_hello(data) → JA3 hash (MD5)
    │
    ▼
classification/ja4.py
    parse_tls_client_hello_ja4(data) → JA4 fingerprint (a_b_c)
    parse_tls_server_hello_ja4s(data) → JA4S (if server response captured)
    parse_http_ja4h(method, headers, cookie) → JA4H (for HTTP events)
    parse_x509_ja4x(cert_der) → JA4X (for captured certificates)
    │
    ▼
classification/fingerprint_extractor.py
    extract_all_fingerprints() → list of Fingerprint objects
    store_fingerprints() → attacker_fingerprints table
    │
    ▼
ja4_fingerprints table (per-event storage)
    │
    ▼
src/honeylens/api.py → lookup_ja4_fingerprint()
    Queries ja4_database for application match
    Fallback: partial match on 'a' component
    │
    ▼
webui/dashboard_ja4.py
    Threat highlighting (cobalt strike, metasploit, etc.)
    TLS version badges (1.3=green, 1.2=amber, older=red)
    Application identification display
```

---

## API Endpoints

| Endpoint | Method | Returns |
|----------|--------|---------|
| `/ja3_stats` | GET | JA3 frequency analysis across all events |
| `/ja4_stats` | GET | JA4+ summary with threat detection |
| `/ja4/detected` | GET | Applications identified in traffic |
| `/ja4/detected/{app}` | GET | Events for specific application |
| `/ja4/database` | GET | Database statistics (total, verified, by type) |
| `/ja4/search?app=` | GET | Search database by application name |
| `/ja4/lookup/{fp}` | GET | Lookup specific fingerprint details |
| `/ja4/{fingerprint}` | GET | Events matching fingerprint |
| `/attacker_fingerprints/{ip}` | GET | All fingerprints for an IP |

---

## Tools

### Import JA4+ database

```bash
python src/honeylens/tools/import_ja4_db.py data/ja4+_db.json          # Full import
python src/honeylens/tools/import_ja4_db.py --stats                     # Show statistics
python src/honeylens/tools/import_ja4_db.py --search "cobalt strike"    # Search
python src/honeylens/tools/import_ja4_db.py --lookup t13d1516h2         # Lookup
```

### Backfill fingerprints from historical events

```bash
python src/honeylens/tools/backfill_ja4.py                    # All events with JA3
python src/honeylens/tools/backfill_ja4.py --limit 1000       # Process max 1000
python src/honeylens/tools/backfill_fingerprints.py           # All fingerprint types
```

---

## Licensing

### JA3 — BSD 3-Clause (fully open)

- **Author:** Salesforce (John Althouse, Jeff Atkinson, Josh Atkins)
- **License:** BSD 3-Clause
- **Repository:** https://github.com/salesforce/ja3
- **Our implementation:** `src/honeylens/classification/ja3.py` — clean-room implementation of the algorithm
- **Status:** No licensing restrictions. Can be used in any project regardless of license.

### JA4 TLS Client — BSD 3-Clause (fully open)

- **Author:** FoxIO (John Althouse)
- **License:** BSD 3-Clause — same as JA3
- **What's covered:** The core JA4 TLS client fingerprinting method only
- **Our implementation:** `parse_tls_client_hello_ja4()` in `src/honeylens/classification/ja4.py`
- **Status:** No licensing restrictions. Can be used in any project.

### JA4S, JA4H, JA4X, JA4T, JA4SSH — FoxIO License 1.1

- **Author:** FoxIO
- **License:** FoxIO License 1.1 (NOT BSD, NOT open source)
- **Repository:** https://github.com/FoxIO-LLC/ja4
- **Key restrictions:**
  - **Permitted:** Internal business use, non-commercial use, security research, education
  - **Permitted:** Integration into open-source tools (as long as FoxIO License retained)
  - **NOT permitted:** OEM/resell as part of a commercial product without FoxIO agreement
  - **NOT permitted:** Sublicensing under a different license
- **Our implementation:** `parse_tls_server_hello_ja4s()`, `parse_http_ja4h()`,
  `parse_x509_ja4x()` in `src/honeylens/classification/ja4.py`

### JA4+ Database (`ja4+_db.json`) — FoxIO License 1.1

- **Size:** 208MB, 36K+ entries, 276K+ fingerprints
- **License:** Same FoxIO License 1.1 as the JA4S/JA4H/JA4X methods
- **Our usage:** Imported into `ja4_database` PostgreSQL table via `src/honeylens/tools/import_ja4_db.py`
- **Attribution:** Required — must credit FoxIO

---

## What to Remove for GPLv3 or BSD Licensing

If HoneyLens were to be released under a fully open license (GPLv3, BSD, MIT, Apache 2.0),
the following FoxIO-licensed components would need to be removed or replaced:

### Must remove (FoxIO License 1.1 — incompatible with GPL/BSD)

| Component | File | What to remove |
|-----------|------|----------------|
| **JA4S** server fingerprinting | `src/honeylens/classification/ja4.py` | `parse_tls_server_hello_ja4s()` function |
| **JA4H** HTTP fingerprinting | `src/honeylens/classification/ja4.py` | `parse_http_ja4h()` function |
| **JA4X** certificate fingerprinting | `src/honeylens/classification/ja4.py` | `parse_x509_ja4x()` function |
| **JA4T** TCP fingerprinting | `src/honeylens/classification/ja4.py` | Any JA4T-related code |
| **JA4+ database** | `data/ja4+_db.json` | Entire 208MB file |
| **Database import tool** | `src/honeylens/tools/import_ja4_db.py` | Entire file (operates on FoxIO data) |
| **JA4S/H/X known fingerprints** | `src/honeylens/classification/ja4.py` | `KNOWN_JA4S`, `KNOWN_JA4H`, `KNOWN_JA4X` dicts |
| **Database schema** | `src/honeylens/db/migrations/` | `ja4_database` table (stores FoxIO data) |
| **API lookup** | `src/honeylens/api.py` | `lookup_ja4_fingerprint()` — queries FoxIO database |
| **Dashboard JA4 pages** | `src/honeylens/webui/dashboard_ja4.py` | JA4S/JA4H/JA4X display sections |

### Can keep (BSD 3-Clause — compatible with everything)

| Component | File | License |
|-----------|------|---------|
| **JA3** client fingerprinting | `src/honeylens/classification/ja3.py` | BSD 3-Clause (Salesforce) |
| **JA3S** server fingerprinting | `src/honeylens/classification/ja3.py` | BSD 3-Clause (Salesforce) |
| **JA4 TLS client** fingerprinting | `src/honeylens/classification/ja4.py` | BSD 3-Clause (FoxIO) |
| **JA3 known fingerprints** | `src/honeylens/classification/ja3.py` | Community data, no license restriction |
| **JA4 known fingerprints** | `src/honeylens/classification/ja4.py` | `KNOWN_JA4` dict (JA4 TLS client only) |
| **Fingerprint extractor** | `src/honeylens/classification/fingerprint_extractor.py` | Our code |
| **Backfill tools** | `src/honeylens/tools/backfill_ja4.py` | Our code |
| **ja4_fingerprints table** | `src/honeylens/db/migrations/` | Our schema (stores our computed fingerprints) |

### Replacement options for removed components

| Removed | Replacement | License |
|---------|-------------|---------|
| JA4S/H/X/T | Implement HASSH (SSH fingerprinting, BSD) | BSD 3-Clause |
| JA4+ database | Build own fingerprint DB from traffic observation | N/A (own data) |
| JA4+ database | Use ja3er.com community database (JA3 only) | Open |
| JA4H | HTTP header ordering as custom fingerprint | Our code |
| JA4X | Certificate field hashing (custom implementation) | Our code |
| JA4T | TCP/IP stack fingerprinting (p0f-style) | GPL or custom |

### Impact assessment

Removing the FoxIO-licensed components would:

1. **Lose application identification from 276K fingerprints** — this is the biggest loss.
   The JA4+ database is what turns a hash into "Chrome 120" or "CobaltStrike".
2. **Lose server fingerprinting (JA4S)** — we'd still have JA3S (BSD) which serves the same purpose.
3. **Lose HTTP fingerprinting (JA4H)** — could be reimplemented as a custom header-order hash.
4. **Lose certificate fingerprinting (JA4X)** — could be reimplemented with different field selection.
5. **Keep JA3 + JA4 TLS client** — the two most valuable fingerprinting methods are both BSD-licensed.

**Bottom line:** JA3 + JA4 TLS client cover ~80% of the fingerprinting value and are fully BSD.
The FoxIO-licensed extensions (JA4S/H/X/T) and the 276K fingerprint database add application
identification, which is valuable but not essential. A BSD/GPL release would still have strong
TLS fingerprinting — just without the "this is Chrome 120" label from the FoxIO database.
