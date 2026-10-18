> **Ported from the 0.9 documentation set, 2026-10-12.** Design/proposal carried into the 1.0 line. Partially realised in 1.0: `src/honeylens/analysis/hunt_queue.py`, `src/honeylens/siem/manager.py` and `src/honeylens/routes/hunting.py` already exist; the full `work_jobs` model below remains a proposal. Paths are under `src/honeylens/`.

# HoneyLens Asynchronous Job Queue Architecture

**Design date:** 2026-07-26
**Scope:** local AI analysis, cloud AI analysis, attacker hunting, and WebUI job feedback
**Status:** Proposed

## Executive summary

Long-running HoneyLens operations currently execute inside the HTTP request that starts them. The browser therefore waits while the API performs local Ollama analysis, calls a cloud AI provider, collects OSINT, builds an attacker profile, or chains one operation into another.

The recommended solution is a persistent PostgreSQL-backed execution queue with three worker classes:

- local AI worker;
- cloud AI worker;
- attacker hunting worker.

The API should validate and enqueue work, then return `202 Accepted` immediately. The WebUI should display the queued/running state independently of the page that initiated the operation. Results should continue to be written to the existing domain tables such as `ai_analysis`, `claude_analysis_log`, and `attacker_profiles`.

PostgreSQL is recommended for the first implementation because it is already a required HoneyLens component, provides transactions and atomic locking, and avoids adding Redis, Celery, Kafka, or another operational dependency before queue scale requires one.

## Goals

1. Release the browser and API request immediately after a task is accepted.
2. Preserve work across API restarts and browser navigation.
3. Prevent duplicate analysis and duplicate hunting jobs.
4. Support priorities, retries, backoff, cancellation, and dead-letter handling.
5. Make task ownership and current state visible to operators.
6. Enforce cloud budgets and provider rate limits centrally.
7. Allow controlled worker concurrency without processing a job twice.
8. Reuse current analysis, profiling, and result-storage code.
9. Prepare the execution model for future multi-sensor operation.

## Non-goals

The first version should not:

- introduce Kafka solely for task execution;
- require Redis or Celery;
- replace existing result tables;
- rewrite the AI analyzers or attacker profiler;
- implement distributed fleet scheduling;
- provide arbitrary user-defined jobs;
- guarantee exactly-once external side effects without idempotency support.

The practical delivery guarantee is **at-least-once execution with idempotent task handlers and deduplicated active jobs**.

## Current behaviour

### Local AI analysis

`POST /ai/analyze/{event_id}` performs the complete operation before returning:

- event lookup and validation;
- known-scanner checks;
- Ollama availability checks;
- local triage;
- local or cloud deep analysis;
- result storage;
- attempted automatic attacker profiling.

Although the route is declared `async`, important work uses synchronous clients and database calls. This can block an API event-loop worker in addition to keeping the browser request open.

### Cloud deep analysis

`POST /ai/deep-analyze/{event_id}` selects OpenAI or Claude and invokes the provider before returning the response.

FastAPI may execute the synchronous endpoint in a thread pool, which reduces event-loop blocking, but:

- the browser still waits;
- an API worker thread remains occupied;
- provider timeouts become HTTP timeouts;
- API restart loses the in-flight request;
- repeated clicks can start repeated paid operations.

### Attacker hunting

`POST /attacker_hunting/{ip}/hunt` waits for:

- database statistics;
- OSINT provider calls;
- geolocation and attribution;
- profile AI analysis;
- profile storage.

The operation can be slow and is affected by external provider latency and rate limits.

### Existing daemons

HoneyLens already has AI and profiler services, but they derive pending work from domain data:

- the AI daemon selects events without `ai_analysis`;
- the profiler selects qualifying or stale IPs;
- bulk hunting mostly changes hunting state rather than creating an explicit execution request.

This model does not provide:

- an explicit job ID;
- atomic ownership of a job;
- lease expiry;
- per-job retry state;
- durable error information;
- cancellation;
- direct manual-job priority;
- reliable WebUI progress reporting.

### Existing `/ai/queue`

The existing `/ai/queue` route is an analyst review queue containing suspicious or critical results that have not been reviewed. It should retain that purpose.

The execution queue should use separate routes and storage to avoid confusing:

- work waiting to be executed;
- analysis results waiting for human review.

## Architectural overview

```text
WebUI / API client
        |
        | POST action
        v
HoneyLens API
  - authenticate
  - authorise
  - validate subject
  - apply deduplication
  - enqueue job
        |
        | 202 Accepted + job_id
        v
PostgreSQL work_jobs
        |
        +-------------------+--------------------+
        |                   |                    |
        v                   v                    v
Local AI worker      Cloud AI worker       Hunting worker
  Ollama              OpenAI/Claude          OSINT + profile AI
        |                   |                    |
        +-------------------+--------------------+
                            |
                            v
Existing result tables
  ai_analysis
  claude_analysis_log
  attacker_profiles
  attacker_osint_log
                            |
                            v
WebUI polling or SSE
  queued / running / succeeded / failed
```

## Job types

### `local_ai`

Subject: event ID.

Responsibilities:

- local Ollama triage;
- optional local deep analysis;
- writing the normal `ai_analysis` result;
- recording model and prompt versions;
- optionally enqueueing a follow-up job according to policy.

Recommended worker concurrency: one job per GPU/model instance by default.

### `cloud_ai`

Subject: event ID.

Responsibilities:

- selecting the configured cloud backend;
- checking availability and budget immediately before dispatch;
- OpenAI or Claude analysis;
- result and cost storage;
- optional policy-driven hunting enqueue.

Recommended worker concurrency: two to four jobs initially, further constrained by provider-specific rate and spending limits.

### `hunt`

Subject: IP address.

Responsibilities:

- event-statistics snapshot;
- OSINT collection;
- attribution and normalisation;
- profile AI assessment;
- writing `attacker_profiles` and OSINT audit data.

Recommended worker concurrency: one or two initially, with separate per-provider semaphores or rate limits.

## Database model

### `work_jobs`

Suggested schema:

```sql
CREATE TABLE work_jobs (
    id                  UUID PRIMARY KEY,
    kind                VARCHAR(32) NOT NULL,
    subject_type        VARCHAR(16) NOT NULL,
    subject_key         VARCHAR(128) NOT NULL,

    state               VARCHAR(16) NOT NULL DEFAULT 'queued',
    priority            SMALLINT NOT NULL DEFAULT 30,

    payload             JSONB NOT NULL DEFAULT '{}'::jsonb,
    result              JSONB,
    result_ref          VARCHAR(256),

    requested_by        VARCHAR(128),
    requested_via       VARCHAR(32) NOT NULL DEFAULT 'api',
    dedupe_key          VARCHAR(256) NOT NULL,
    parent_job_id       UUID REFERENCES work_jobs(id),

    attempts            INTEGER NOT NULL DEFAULT 0,
    max_attempts        INTEGER NOT NULL DEFAULT 3,
    available_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    lease_owner         VARCHAR(128),
    lease_expires_at    TIMESTAMPTZ,
    heartbeat_at        TIMESTAMPTZ,

    progress_percent    SMALLINT,
    progress_stage      VARCHAR(64),
    progress_message    TEXT,

    error_code          VARCHAR(64),
    error_message       TEXT,
    error_details       JSONB,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at          TIMESTAMPTZ,
    finished_at         TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (kind IN ('local_ai', 'cloud_ai', 'hunt')),
    CHECK (subject_type IN ('event', 'ip')),
    CHECK (state IN (
        'queued', 'running', 'succeeded',
        'failed', 'dead', 'cancelled'
    )),
    CHECK (priority BETWEEN 0 AND 100),
    CHECK (
        progress_percent IS NULL
        OR progress_percent BETWEEN 0 AND 100
    )
);
```

Recommended indexes:

```sql
CREATE INDEX idx_work_jobs_claim
    ON work_jobs (kind, priority DESC, available_at, created_at)
    WHERE state = 'queued';

CREATE INDEX idx_work_jobs_active_subject
    ON work_jobs (subject_type, subject_key, state);

CREATE INDEX idx_work_jobs_recent
    ON work_jobs (created_at DESC);

CREATE INDEX idx_work_jobs_lease
    ON work_jobs (lease_expires_at)
    WHERE state = 'running';

CREATE UNIQUE INDEX uq_work_jobs_active_dedupe
    ON work_jobs (dedupe_key)
    WHERE state IN ('queued', 'running');
```

Use the PostgreSQL UUID generation method already approved for the target environment. A generated UUID, ULID stored as text, or application-generated UUID is acceptable as long as identifiers are unpredictable and stable.

### `work_job_events`

An optional append-only history table is recommended:

```sql
CREATE TABLE work_job_events (
    id          BIGSERIAL PRIMARY KEY,
    job_id      UUID NOT NULL REFERENCES work_jobs(id) ON DELETE CASCADE,
    event_type  VARCHAR(32) NOT NULL,
    actor       VARCHAR(128),
    details     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

Useful event types:

- `created`;
- `deduplicated`;
- `claimed`;
- `heartbeat`;
- `progress`;
- `retry_scheduled`;
- `succeeded`;
- `failed`;
- `dead`;
- `cancel_requested`;
- `cancelled`.

This table provides an audit trail without repeatedly expanding the main job row.

## State machine

```text
                  transient failure
                ┌──────────────────┐
                v                  |
queued ──────> running ──────> queued
  |              |   |
  |              |   +────────> succeeded
  |              |
  |              +────────────> failed ─────> dead
  |                                  attempts exhausted
  |
  +────────────> cancelled

running ───────> cancelled
      cooperative cancellation
```

Interpretation:

- `queued`: available now or scheduled through `available_at`;
- `running`: claimed by one worker with an active lease;
- `succeeded`: domain result was committed successfully;
- `failed`: most recent attempt failed but may be retried;
- `dead`: no automatic attempts remain or error is permanent;
- `cancelled`: operator cancelled the job before completion.

For simpler queries, a retryable failure may transition directly from `running` to `queued`, while recording the failure in `work_job_events`. The `failed` state can be reserved for jobs awaiting an operator retry decision.

## Atomic claim and lease

A worker must claim a job in one transaction:

```sql
WITH candidate AS (
    SELECT id
    FROM work_jobs
    WHERE state = 'queued'
      AND kind = ANY(%s)
      AND available_at <= NOW()
    ORDER BY priority DESC, created_at ASC
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
UPDATE work_jobs j
SET state = 'running',
    lease_owner = %s,
    lease_expires_at = NOW() + INTERVAL '90 seconds',
    heartbeat_at = NOW(),
    started_at = COALESCE(started_at, NOW()),
    attempts = attempts + 1,
    updated_at = NOW()
FROM candidate
WHERE j.id = candidate.id
RETURNING j.*;
```

Key properties:

- `SKIP LOCKED` allows several workers to claim different jobs;
- priority controls operator-visible urgency;
- oldest-first ordering avoids starvation;
- the lease allows recovery after a process or host crash.

Long jobs must extend their lease periodically. A reaper should detect expired leases and:

- return retryable jobs to `queued`;
- increment or preserve attempt accounting according to one documented rule;
- move exhausted jobs to `dead`;
- record the recovery event.

The worker must verify its `lease_owner` when writing progress or final state.

## Deduplication and idempotency

Suggested keys:

```text
local-ai:{event_id}:{model}:{prompt_version}
cloud-ai:{event_id}:{provider}:{model}:{prompt_version}
hunt:{ip}:{profile_version}
```

Behaviour:

1. If an equivalent `queued` or `running` job exists, return that job.
2. If a recent successful result is still valid, the API may return the cached result or the completed job.
3. `force=true` creates a new generation only for authorised users.
4. Domain writes use upsert or compare-and-set logic.
5. Paid calls should receive an idempotency key where the provider supports one.

The unique partial index protects against double-clicks and concurrent API requests.

## Priority model

Recommended initial priorities:

| Source | Priority |
|---|---:|
| Manual cloud AI | 100 |
| Manual local AI | 95 |
| Manual hunt | 90 |
| Automatic critical analysis | 80 |
| Automatic suspicious analysis | 60 |
| Policy-driven auto-hunt | 50 |
| Normal background analysis | 30 |
| Scheduled re-profiling | 20 |
| Bulk hunt or backfill | 10 |

Within the same priority, process the oldest job first.

If low-priority starvation is observed, implement priority aging, for example increasing effective priority based on queue age without changing the stored base priority.

Each worker type has a separate capacity pool. A flood of hunting jobs must not prevent a manually requested cloud analysis from running.

## Retry policy

### Retryable

- network timeout;
- temporary DNS or connection failure;
- provider HTTP `429`;
- provider HTTP `5xx`;
- temporary Ollama unavailability;
- recoverable PostgreSQL transaction or connection failure;
- expired worker lease.

### Permanent

- invalid event ID or IP;
- missing subject;
- access denied;
- disabled external AI;
- missing required configuration;
- rejected payload;
- budget exhausted for the relevant period;
- unsupported model or provider;
- deterministic parsing or validation failure after a successful provider response, unless a specific repair attempt is implemented.

Suggested backoff:

```text
attempt 1: 15 seconds
attempt 2: 60 seconds
attempt 3: 5 minutes
attempt 4: 20 minutes
```

Provider `Retry-After` should override the local delay where safe.

Store a short redacted operator-facing message separately from detailed internal error metadata.

## Budget and rate limiting

Cloud budgets must be checked:

1. when the API accepts a request, to provide immediate feedback;
2. immediately before the worker sends the paid request.

The worker-side check is authoritative because queued work may wait until the budget changes.

Recommended controls:

- daily and monthly cost caps;
- maximum concurrent calls per provider;
- request-per-minute and token-per-minute limits;
- maximum automatic cloud jobs per source IP;
- maximum automatic cloud jobs per event;
- manual priority without bypassing the configured hard spending cap;
- circuit breaker after repeated provider failures.

When the hard budget is exceeded, mark the job with a permanent `budget_exceeded` outcome rather than repeatedly retrying.

## Automatic job chaining

Automatic hunting is currently initiated from several places. The target design should centralise it in job-completion policy.

Example:

```text
local_ai succeeded
  └─ if configured and classification is suspicious/critical
       └─ enqueue cloud_ai

cloud_ai succeeded
  └─ if policy matches
       └─ enqueue hunt
```

Suggested auto-hunt policy:

- verdict is `CRITICAL` or `HIGH`;
- or novelty is at least 7;
- or a CVE/KEV target is identified;
- or the operator requested hunting explicitly;
- known research scanners are excluded unless forced;
- an active or sufficiently fresh hunt job/profile suppresses duplication.

The WebUI must not independently start auto-hunting after receiving an AI result. It should only display the jobs created by server-side policy.

Use `parent_job_id` to show why a follow-up job exists.

Automatic chaining must be configurable. A deployment may want:

- local-only analysis;
- local analysis with manual cloud escalation;
- automatic cloud escalation;
- automatic hunting only for high-confidence cases.

## API contract

Existing action URLs can remain as compatibility adapters.

### Enqueue local AI

```http
POST /ai/analyze/{event_id}?engine=local
```

Response:

```http
HTTP/1.1 202 Accepted
Location: /jobs/019...
Retry-After: 2
```

```json
{
  "status": "queued",
  "job_id": "019...",
  "kind": "local_ai",
  "subject_type": "event",
  "subject_key": "event-id",
  "priority": 95,
  "deduplicated": false,
  "status_url": "/jobs/019..."
}
```

### Enqueue cloud AI

```http
POST /ai/deep-analyze/{event_id}
```

Returns the same envelope with `kind: "cloud_ai"`.

The legacy `/ai/claude-analyze/{event_id}` route should call the same enqueue service and remain an alias until it can be retired.

### Enqueue hunting

```http
POST /attacker_hunting/{ip}/hunt
```

Returns the same envelope with `kind: "hunt"`.

### Job status

```http
GET /jobs/{job_id}
```

Example:

```json
{
  "id": "019...",
  "kind": "cloud_ai",
  "state": "running",
  "subject_type": "event",
  "subject_key": "event-id",
  "priority": 100,
  "attempts": 1,
  "progress": {
    "percent": 55,
    "stage": "provider_request",
    "message": "Waiting for OpenAI"
  },
  "created_at": "2026-07-26T10:00:00Z",
  "started_at": "2026-07-26T10:00:01Z",
  "result_url": null
}
```

Recommended routes:

```text
GET  /jobs/{job_id}
GET  /jobs
GET  /jobs/summary
POST /jobs/{job_id}/cancel
POST /jobs/{job_id}/retry
```

Useful filters:

```text
state
kind
subject_type
subject_key
requested_by
created_after
```

Only administrators should create paid or operationally sensitive work unless a more granular analyst role is explicitly designed.

## WebUI behaviour

### Immediate response

After an action:

1. submit the request;
2. receive `202 Accepted`;
3. change the button to `Queued`;
4. store or register the returned job ID;
5. release the UI immediately;
6. allow navigation away from the page;
7. continue showing job state globally.

The initiating drawer or page must not be the only place where progress exists.

### Global job indicator

Add a compact indicator to the application shell:

```text
Jobs: 2 running · 4 queued · 1 failed
```

Selecting it opens a job tray:

```text
RUNNING   Cloud AI   Event 8ab3...   Provider request
RUNNING   Hunt       83.12.x.x       OSINT 4/7
QUEUED    Local AI   Event 9fc2...   Position 1
FAILED    Cloud AI   Event 71dd...   Budget exceeded
```

### Per-subject state

Event and attacker pages should query active/recent jobs for their subject and show:

- `Queued`;
- `Running — local triage`;
- `Running — cloud analysis`;
- `Running — OSINT 4/7`;
- `Completed`;
- `Failed — retry`;
- `Cancelled`.

Refreshing the browser must not lose this state.

### Polling first, SSE later

The first implementation should poll:

- active job detail every two seconds;
- global summary every five to ten seconds;
- back off polling when the tab is hidden;
- stop polling terminal jobs.

Polling is simple and robust across reverse proxies.

Server-Sent Events may be added later:

```text
GET /jobs/stream
```

SSE should be an optimisation, not a prerequisite for correct job execution.

### Notifications

On completion:

- show a non-blocking toast;
- update the relevant button and drawer;
- provide a link to the stored result;
- keep failure messages available in the global job tray;
- do not force a page reload unless the operator requests it.

## Worker design

### Common worker loop

Each worker should:

1. claim one compatible job;
2. establish lease ownership;
3. write a `claimed` event;
4. load and revalidate the subject;
5. execute the existing domain service;
6. update heartbeat/progress;
7. commit domain result;
8. mark the job succeeded;
9. evaluate follow-up policy;
10. enqueue follow-up jobs transactionally where practical.

If no job is available, wait briefly. PostgreSQL `LISTEN/NOTIFY` can later reduce polling latency, but correctness must not depend on notifications because they are not durable.

### Cancellation

Cancellation is cooperative:

- queued jobs can be cancelled immediately;
- running jobs receive a cancellation request;
- workers check between expensive stages;
- an in-flight provider request may not be interruptible;
- a result received after cancellation should be recorded according to one documented policy.

For the first version, queued-job cancellation is sufficient. Running cancellation can follow after worker progress stages are reliable.

### Graceful shutdown

On SIGTERM:

- stop claiming new jobs;
- finish or safely abandon the current stage;
- update the heartbeat;
- release or allow the lease to expire;
- close provider and database clients.

## Refactoring boundaries

Route handlers should not import and orchestrate analyzer internals directly.

Introduce service-level functions such as:

```python
enqueue_local_analysis(...)
enqueue_cloud_analysis(...)
enqueue_hunt(...)
execute_local_analysis_job(...)
execute_cloud_analysis_job(...)
execute_hunt_job(...)
```

The execution functions should:

- accept a stable job payload;
- return a result reference or summary;
- be usable from a worker and tests;
- avoid depending on FastAPI `Request`;
- be idempotent when called again after an uncertain failure.

Existing analyzers and profiler functions can initially be called inside these execution adapters.

## Observability

Expose at least:

- queued jobs by kind and priority;
- oldest queued-job age;
- running jobs by worker;
- success/failure/dead counts;
- attempts per job;
- duration percentiles by kind;
- provider `429` and `5xx` counts;
- lease expirations;
- deduplicated request count;
- local AI throughput;
- cloud cost by job, model, day, and requester;
- hunting duration by OSINT provider;
- number of policy-created follow-up jobs.

Suggested health rules:

- warning when oldest manual job exceeds a threshold;
- warning when no heartbeat exists for an active worker;
- alert when dead jobs appear;
- alert when cloud failures or lease expirations exceed a threshold;
- explicit degraded state when a worker class is unavailable.

## Security requirements

- Authorise job creation before enqueue.
- Re-authorise sensitive execution policy where configuration may have changed.
- Never store API keys or credentials in job payloads.
- Redact provider errors before returning them to non-admin users.
- Validate `kind`, subject type, event ID, IP, engine, and all options.
- Limit job payload size.
- Use unpredictable job IDs.
- Restrict cancellation and retry to authorised users.
- Record requester identity and origin.
- Apply CSRF protection to browser-backed state-changing routes.
- Prevent job results from rendering attacker-controlled HTML.
- Keep cloud budget controls authoritative in the worker.

## Migration plan

### Phase 0 — Inventory and regression coverage

- Enumerate all manual and automatic AI/hunting entry points.
- Identify duplicated auto-hunt triggers.
- Add tests around current result storage.
- Verify current `profile_ip` call signatures and module import paths.
- Document existing cost and scanner-exclusion behaviour.

**Exit criteria:** every execution path has an owner and a regression test or explicit migration note.

### Phase 1 — Queue foundation

- Add `work_jobs` and optional `work_job_events`.
- Implement enqueue, deduplication, claim, heartbeat, success, retry, dead, and cancel operations.
- Add atomic concurrency tests.
- Add lease-recovery tests.
- Add queue metrics.

**Exit criteria:** multiple test workers cannot execute the same active job.

### Phase 2 — Hunting worker

- Move manual hunt execution behind the queue.
- Convert the current profiler daemon to claim explicit `hunt` jobs.
- Preserve scheduled profiling by enqueueing low-priority jobs.
- Make bulk hunt create explicit jobs.
- Return `202` from the current hunt route.

**Exit criteria:** the browser receives an immediate response and hunting survives API restart.

### Phase 3 — Cloud AI worker

- Move `/ai/deep-analyze` behind `cloud_ai`.
- Centralise backend selection, budgets, rate limits, retries, and cost accounting.
- Keep the Claude-specific URL as an enqueue alias.
- Remove WebUI-driven auto-hunt.

**Exit criteria:** paid calls cannot be duplicated by repeated clicks and do not occupy API requests.

### Phase 4 — Local AI worker

- Convert the existing AI daemon to explicit `local_ai` claims.
- Preserve background discovery by enqueueing qualifying events.
- Use one local worker per GPU/model instance initially.
- Replace newest-first implicit selection with priority plus oldest-first scheduling.

**Exit criteria:** manual jobs pre-empt normal background work without starving older jobs.

### Phase 5 — WebUI job experience

- Add shared job client functions.
- Add global job summary and tray.
- Add per-event and per-IP job state.
- Add polling and completion notifications.
- Preserve state after navigation and reload.
- Add retry/cancel actions for authorised users.

**Exit criteria:** no supported AI or hunting action requires the initiating page to remain open.

### Phase 6 — Hardening

- Add provider circuit breakers.
- Add priority aging if required.
- Add dead-job operator workflow.
- Add SSE if polling load justifies it.
- Add retention cleanup for completed job records.
- Review multi-sensor implications.

## Test plan

### Queue correctness

- two simultaneous enqueue requests produce one active job;
- two workers cannot claim the same job;
- different jobs can be processed concurrently;
- higher priority wins;
- equal priority is oldest-first;
- scheduled jobs are not claimed early;
- expired lease is recovered;
- exhausted retries produce `dead`;
- terminal jobs are never claimed;
- cancellation prevents queued execution.

### Domain integration

- local AI result is written to `ai_analysis`;
- cloud AI result and cost are stored correctly;
- hunting writes one consistent attacker profile;
- follow-up policy enqueues exactly one hunt;
- known scanners are skipped unless forced;
- cached/fresh result policy works;
- prompt/model version changes generate the expected dedupe key.

### Failure handling

- Ollama unavailable;
- cloud timeout;
- cloud `429`;
- cloud `5xx`;
- invalid provider response;
- budget exhausted;
- database disconnect;
- worker crash after provider response but before final job update;
- worker crash after domain result commit;
- API restart after enqueue;
- browser closes immediately after enqueue.

### WebUI

- action returns to an interactive state after `202`;
- queued and running states are distinguishable;
- user can navigate away and still see progress;
- refresh restores job state;
- result appears without repeating the action;
- failures show safe and actionable messages;
- duplicate clicks reuse the active job;
- role restrictions apply to create, retry, and cancel;
- job notifications are keyboard accessible.

## Acceptance criteria

The feature is complete when:

1. local AI, cloud AI, and hunting routes normally return within 500 ms after validation and enqueue;
2. long-running work continues after the initiating browser tab closes;
3. API restart does not lose queued or running work;
4. active duplicate work is prevented;
5. workers recover abandoned jobs through leases;
6. manual jobs receive higher priority than background jobs;
7. cloud spending limits are enforced by workers;
8. WebUI shows queued, running, completed, failed, and cancelled states;
9. results remain in current domain tables;
10. all queue and integration concurrency tests pass.

## Recommended first implementation

The minimum high-value release is:

1. PostgreSQL `work_jobs`;
2. atomic claim using `FOR UPDATE SKIP LOCKED`;
3. one worker for each of `local_ai`, `cloud_ai`, and `hunt`;
4. current action routes changed to enqueue and return `202`;
5. WebUI polling for active job IDs;
6. global job indicator;
7. deduplication, lease recovery, bounded retry, and dead-job visibility.

This removes long-running work from the browser request without introducing unnecessary infrastructure and creates a foundation suitable for future multi-sensor scheduling.
