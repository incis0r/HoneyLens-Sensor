# Hunting in Sensor 1.0

Apply `honeylens-migrate` before starting the API or profiler after an upgrade.
Migration 0009 installs OSINT history and the persistent hunting queue. It is additive;
rollback to the previous application version does not require dropping these tables.

Install `containers/systemd/honeylens-profiler.service` in `~/.config/systemd/user/`,
then `systemctl --user daemon-reload` and `systemctl --user enable --now honeylens-profiler`.
All of this is the **`sensor` service account**, not your login — `sudo -u sensor -i` first,
so `~` is `/home/sensor`. The template uses `~/sensor-1.0/.venv` and `~/honeylens-state/.env`
via `%h`; adjust paths for other layouts. Run `loginctl enable-linger sensor` if it is not
enabled, or the profiler stops the moment nobody is logged in.

`PROFILER_AUTO` controls automatic discovery. Explicit bulk requests run even when it
is false. `PROFILER_MIN_CONNECTIONS`, `PROFILER_MIN_ATTACKS`, `PROFILER_BATCH_SIZE`,
`PROFILER_INTERVAL` and `PROFILER_REPROFILE_INTERVAL` control qualification, batch size,
cycle sleep and reanalysis. A batch is capped at 50. Bulk requests are queued durably,
prioritized ahead of discovery, deleted only after a saved profile, and retried after
five minutes on failure. Requeuing an IP while it is running preserves the new request.
Only one daemon owns the session advisory lock; restarting it releases the lock and
retains any unfinished queue rows.

## AI backend

Default: `PROFILER_AI_PROVIDER=ollama`, using `OLLAMA_URL`, `OLLAMA_TIMEOUT` and
`PROFILER_OLLAMA_MODEL` (or `OLLAMA_DEEP_MODEL`). For Nous set in the **host** environment:

```dotenv
PROFILER_AI_PROVIDER=nous
NOUS_API_KEY=<your key>
PROFILER_NOUS_MODEL=qwen/qwen3-30b-a3b-instruct-2507
PROFILER_AI_MAX_TOKENS=1024
```

Nous uses `https://inference-api.nousresearch.com/v1/chat/completions`. No new SDK is
required. Model selection is configurable; prices may change. As checked on 2026-10-02,
[the catalog](https://portal.nousresearch.com/models) offers the configured Qwen model
at approximately $0.05 input / $0.19 output per million tokens. Returned usage/cost
metadata is saved under `attacker_profiles.osint_data._ai`. The 1024-token output limit
bounds each response, not total account spend. Backend errors produce an explicit
unavailable status and do not erase a previous successful assessment.

Only the existing structured profile summary is sent: IP, OSINT summary, classifications,
counts and attribution candidates; raw honeypot payloads and captured credentials are
not included. Missing intelligence is marked unknown. These model assessments still
require analyst judgment; they do not prove exploitation or attribution.

The event analyzer has a separate triage/deep pipeline. To route both stages through
Nous, install the package with `pip install '.[openai]'`, install
`containers/systemd/honeylens-ai-analyzer.service`, and configure:

```dotenv
AI_PROVIDER=nous
AI_ANALYSIS_ENABLED=true
USE_EXTERNAL_AI=true
NOUS_API_KEY=<your key>
NOUS_BASE_URL=https://inference-api.nousresearch.com/v1
NOUS_TRIAGE_MODEL=qwen/qwen3-30b-a3b-instruct-2507
NOUS_DEEP_MODEL=qwen/qwen3-30b-a3b-instruct-2507
```

The analyzer performs triage first and runs deep analysis only for suspicious or
critical events with a novelty score of at least five. Both calls share the normal
daily and monthly external-AI budget limits.

## Threat feed

Set `BLOG_ENABLED=true`, `BLOG_URL`, `BLOG_API_KEY`, `BLOG_BASIC_USER`, and
`BLOG_BASIC_PASS` in the profiler host environment. **Publishing is manual only:**
nothing is posted to the blog automatically. The operator reviews hunting results and
publishes the chosen candidates — through the export publish route, or the
`blog_publisher` CLI with `--trigger manual`. A completed profile is never
auto-published. The existing private-address, sensor-address, known-scanner,
credential, and OPSEC filters still apply to every manual publish.
For a direct origin route with a private CA, set `BLOG_CA_BUNDLE` to the pinned
certificate path. This path takes precedence over the boolean `BLOG_VERIFY_TLS` flag.

`.nouresearch`, `.creds*` and `.env*` are excluded from container build contexts;
`.nouresearch` is also gitignored. Deploy the key only to the host `.env` with mode 0600,
not to container variables, command-line arguments, images, or commit messages.

## Log coordination and rollout

Writers and cleanup share a persistent `<log>.lock` sidecar using `flock`. Never delete
these sidecars while services are running. Ingest snapshots the byte length under the
lock and parses only that snapshot; writers continue while database work runs. A
separate `<log>.ingest.lock` serializes overlapping honeypot ingests through commit
and cleanup. Cleanup never replaces an unwritable inode: it preserves the file and
reports the error so an open vendor writer cannot become detached.

All cooperating writers must be upgraded with the host ingest. Build images first,
stop ingest and the affected honeypots, switch the installed package/images, then
restart writers and ingest. Keep previous images and the old package for rollback.
Unmodified external log writers cannot be protected by an advisory lock they ignore.
Incomplete, invalid or rejected input records are retained with an ingest error rather
than discarded; inspect/repair the source record before retrying that file.

## Verification

`python scripts/check_hunting_db.py` runs migration and queue/count tests against
session-local PostgreSQL fixtures; it does not modify production rows or contact AI.

After deployment check `systemctl --user status honeylens-profiler`, the queue's
`attempts/last_error/retry_at`, recent `attacker_osint_log` entries, profile timestamps,
and `osint_data->'_ai'`. Send an ordinary NetScaler request with a unique query marker,
wait for ingest, then verify its source, protocol port, metadata and full payload.

### Provider availability

ThreatFox requires `OSINT_THREATFOX_KEY` (the `Auth-Key` from
<https://threatfox.abuse.ch/api/>). Without it the provider is disabled; an
authentication error is never treated as an empty IOC result. Feodo uses the
published JSON IOC feed at <https://feodotracker.abuse.ch/downloads/ipblocklist.json>.
A failed or malformed feed refresh is reported as an error, including when an
expired cache exists, so an outage does not silently clear threat evidence.

On memory-constrained hosts, stop and start containers **sequentially**. A parallel
restart of 38 containers on a host with 768 MB of RAM caused Podman startup timeouts during
the 2026-10-02 rollout. Prepare images first and bring the API/ingest back as soon as
the package is installed and the updated writers are ready.

## The attacker map needs outbound HTTPS

The hunting map is the one part of the dashboard that is not self-contained. It loads its
library from `cdnjs.cloudflare.com` and its basemap tiles from `server.arcgisonline.com`,
both keyless and both **outbound from the browser**, not from the sensor. On a host whose
egress is filtered, or for an analyst on a restricted network, the page renders and the map
is simply blank — nothing in the logs says why, because nothing failed on the sensor.

Two consequences worth knowing before you change anything there:

- The dashboard's `Content-Security-Policy` lists exactly these origins (plus
  `api.first.org` for EPSS lookups). Swapping the tile provider or the CDN means editing the
  policy in `honeylens/api.py` as well, or the browser drops the new source without a word.
  `tests/test_webui_security_headers.py` reads the dashboard source, collects the origins the
  pages load from and fails when one is missing from the policy, so a forgotten swap is
  caught at test time rather than by an analyst staring at an empty map.
- `Cross-Origin-Embedder-Policy` is deliberately not set for the same reason. `require-corp`
  would block both of these, as neither opts in with CORP headers. A scanner will ask for it;
  setting it blanks this map.

If the map must work without internet access, host the library and a tile set locally and
point both at the sensor's own origin — then the CSP needs nothing but `'self'`.
