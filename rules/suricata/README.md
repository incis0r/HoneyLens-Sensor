# HoneyLens Suricata rules

Our own Suricata signatures, for CVEs and decoys the ET Open ruleset does not cover (or did
not cover when the rule was written). They are loaded alongside ET Open, not instead of it.

Until 2026-10-25 these twelve files existed **only as single copies on sensors** and in no
two identical sets. They are here now so that losing a host does not lose a signature.

## What was recovered, and from where

`sensor-a` carried the largest set of *files*, and eleven of its twelve were byte-identical
wherever they appeared. It was not the superset — `prod` keeps the same rules in a different
shape and turned out to hold four that existed nowhere else:

| Host | How it stores them | Rules loaded |
|---|---|---|
| `prod` | `local.rules` (48) + `honeylens-wago-wbm.rules` (10), both named explicitly in `rule-files:` | **58 — the most on the fleet** |
| `sensor-a` | 12 files via the `honeylens-*.rules` glob | 54 |
| `sensor-e` | 11 files (no `ai-canary`) | 44 |
| `sensor-f` | 9 files (no `ai-canary`, `cisco-anyconnect`, `wago-wbm`) | 38 |
| `sensor-b`, `sensor-c` | nothing | 0 |

Looking only at files matching `honeylens-*.rules` made `prod` read as the worst-covered host
when it was the best. Its 48-rule `local.rules` is invisible to that glob, and `sid:9026311`
through `9026314` — the rondo-actor UA literal, the email-shape User-Agent, the SSL-VPN
`vpnupload.cgi` probe and the PAN-OS captive-portal scanner UA family — lived there and only
there. They are in `honeylens-cve-2026-0300.rules` now, with their original block header,
because their sids continue that file's block and that is where they were authored.

The twelfth, `honeylens-cve-2026-49975.rules`, existed in two versions. The difference is one
comment line: `sensor-f`'s older copy names `hp_nginx_rift.py`, `sensor-a`'s names `hp_nginx.py`. All
five rules are identical, same sids at `rev:1`. `hp_nginx.py` and `h2bomb.py` are what the
repository actually contains, so `sensor-a`'s copy is the accurate one and is the one committed.

## Conventions these files follow

- **sid range `9026300`–`9026799`**, grouped per file; ET Open uses `2000000`–`2999999`, so
  there is no collision. Allocated blocks:
  `0300`–`0314` cve-2026-0300 (incl. the four recovered from `prod`) · `0330`–`0332` cve-2026-0257 · `0420`–`0424` cve-2026-42945 ·
  `0500`–`0503` cve-2026-23918 · `0700`–`0704` cve-2026-49975 · `0720`–`0721` cve-2026-25243 ·
  `0725`–`0726` cve-2026-25589 · `0730`–`0732` cve-2026-42533 · `0740`–`0742` ai-canary ·
  `0750`–`0759` wago-wbm · `0760`–`0763` cisco-anyconnect · `0770`–`0773` cve-2026-88771.
  Take the next free block for a new file and keep one file per CVE or subject.
- Every `msg` starts with `HONEYLENS` — 58 of 58 — which is how our alerts are told apart
  from ET's in `eve.json` and in the hunting queries.
- `$HOME_NET` / `$EXTERNAL_NET` only; no literal sensor addresses. The IPv4 literals that do
  appear are **attacker** addresses used as indicators, the same class of content as
  the internal IOC notes — treat those the same way when deciding what goes to a public branch.
- 58 alert rules in total. That figure is checkable from outside: a host loading these reports
  58 more `rules_loaded` than its `suricata.rules` holds `^alert` lines (59 in practice — every
  host counts one rule beyond its `^alert` lines regardless).

## Installing them on a sensor

They are read by Suricata, not by Python, so they are not part of the `honeylens` package and
a code deploy does not carry them. Install path and ownership, matching the hosts that already
work:

```bash
sudo install -m 0644 -o root -g suricata rules/suricata/honeylens-*.rules \
     /var/lib/suricata/rules/
```

Then make sure `/etc/suricata/suricata.yaml` globs them:

```yaml
rule-files:
  - suricata.rules
  - honeylens-*.rules
```

Apply with `sudo systemctl reload suricata` (SIGUSR2, no capture downtime; Suricata keeps the
old ruleset if the new one fails to parse).

**Verify in the engine, not on disk.** The file being present proves nothing about what is
detecting:

```bash
sudo suricatasc -c 'ruleset-stats'   # rules_loaded should rise by 58; rules_failed must stay 0
```

The reload takes about 40 seconds. A `ruleset-stats` query inside that window still reports the
old count and looks exactly like a failed reload — wait for `rule reload complete` in
`journalctl -u suricata`.

`suricata-update` rewrites only `suricata.rules` and never touches these files, so the daily
`sensor-suricata-update.timer` cannot overwrite them.

**Read the host's `rule-files:` stanza before adding the glob.** On `prod` it already names
`honeylens-wago-wbm.rules` explicitly, so adding the glob loaded that file twice; the duplicate
sids aborted the whole load with `error parsing signature … sid:9026759` and
`Loading signatures failed`. Suricata kept the previous ruleset and detection never lapsed, but
a *restart* would have refused to come up. The glob and an explicit entry for the same file
cannot coexist. `prod` is therefore left on its own explicit `rule-files:` entries — it already
loads all 58 — and converging it on the glob means removing `local.rules` and the `wago` line in
the same edit.
