# AegisFlow Windows Endpoint Agent

Feature Part 2 of the Windows Endpoint Analyzer. A standalone Python
process (no Django, not importable by the backend) that runs on a pilot
Windows endpoint, reads a narrow slice of the Event Log, drops
verifiable noise locally, and ships the rest to the AegisFlow backend.

- **In scope (this part):** Event ID 4688 (process creation) on the
  `Security` channel and Event ID 4104 (PowerShell script-block logging)
  on `Microsoft-Windows-PowerShell/Operational`; local noise
  suppression; durable buffering; batched send with retry/backoff;
  one-time enrollment.
- **Part 4 (packaging):** `aegis-agent.exe` (PyInstaller), a pywin32
  Windows service, and an Inno Setup installer -- see
  [`packaging/`](packaging/README.md).
- **Not here:** correlation / AI triage (Part 3), the work-queue UI
  (Part 5), any file-system or registry monitoring (later).

## Layout

```
aegis_agent/
  events.py          EventRecord + Event Log XML parsers (4688 / 4104)
  filters.py         noise-suppression rules (NOT suspicion scoring)
  spool.py           pending.jsonl + state.json: crash-safe buffer & bookmarks
  client.py          urllib client for /endpoints/api/{enroll,ingest}/
  backoff.py         retry timing
  runner.py          the poll -> filter -> spool -> send loop
  config.py          config.toml loader (stdlib tomllib)
  cli.py / __main__  entry point
  sources/
    base.py          EventSource interface
    fake.py          scripted source for tests / --dry-run
    windows.py       real win32evtlog source  <-- the only un-unit-tested code
```

## Running

```bash
cp config.example.toml config.toml       # then edit, or set AEGIS_AGENT_TOKEN
python -m aegis_agent run --config config.toml
python -m aegis_agent run --config config.toml --once      # single tick
python -m aegis_agent run --config config.toml --dry-run   # read real log, never POST
```

Subcommands:

| Command | Purpose |
|---|---|
| `run --config PATH` | the agent loop (enroll once, then poll/filter/spool/send) |
| `write-config --out PATH --base-url U --token T --display-name N` | render a `config.toml` from explicit values (the installer uses this so it never hand-escapes TOML) |
| `enroll-check --config PATH` | run the enroll call once, bounded; print whether the backend was reached and the effective (possibly auto-suffixed) name. Exit 0 **only** on a confirmed connection |
| `service <install\|start\|stop\|remove> …` | Windows only; pass-through to pywin32's service control |

The enrollment token comes from `manage.py createendpoint` on the
backend (printed once). Put it in `config.toml` under
`server.enrollment_token`, or leave that blank and export
`AEGIS_AGENT_TOKEN` (the env var wins). The token is never logged.

## What it sends

Each event becomes one ingest item:

```json
{
  "event_type": "Security/4688",
  "occurred_at": "2026-02-11T14:22:07.123456Z",
  "payload": {
    "agent_event_id": "WIN-PILOT-01|Security|884412",
    "channel": "Security",
    "record_id": 884412,
    "computer": "WIN-PILOT-01",
    "data": { "new_process_name": "...", "parent_process_name": "...", "command_line": "...", ... }
  }
}
```

Batches go to `POST /endpoints/api/ingest/` with
`Authorization: Bearer <token>`, at most `max_batch` (<= server's 500)
events and `max_batch_bytes` per request, every 60-120 s.

## Filtering (noise suppression only)

Filters remove events that are verifiably uninteresting *in isolation*.
They do **not** score suspicion -- that is Part 3. Every suppressed
event is logged with its rule and reason; nothing is dropped silently.

- **4688:** a short list of fixed OS parent/child pairs from
  `C:\Windows\System32\` with a canonical (or absent) command line --
  the session-0 / logon startup chain, plus `svchost.exe` (from
  `services.exe`, with `-k`) and `conhost.exe` (canonical args). Any
  deviation -- different parent, non-system path, unusual command line
  -- is kept.
- **4104:** empty/whitespace-only script blocks, plus an
  operator-supplied exact-match allowlist (empty by default).

Tune via `[filters]` in the config: `disabled_rules`,
`allowlist_script_blocks`, `extra_suppress`.

## Durability

A filtered-in event is fsync'd to `state_dir/pending.jsonl` **before**
the per-channel read bookmark in `state_dir/state.json` advances. A
crash or failed send loses nothing; de-dup by `agent_event_id` makes the
append idempotent.

**A tick drains the whole backlog**, not one batch — repeated sends
until the spool is empty, a send fails, or `max_batches_per_tick` (20)
is hit. So a healthy backend keeps the buffer near empty regardless of
event rate; it only grows during an actual outage.

**Backpressure, not dropping.** When the buffer hits `buffer_max_events`
the agent stops advancing the read bookmark and leaves new events in the
Windows Event Log until the buffer drains. Nothing is discarded to stay
under the cap. The only unavoidable loss is a Windows Event Log that
rotates past events the agent never read (a very long outage on a very
busy machine) — and `sources/windows.py` detects that and logs
`GAP on <channel>: ... ~N event(s) were lost` with a count.

A batch the server rejects as malformed (HTTP 400) is moved to
`state_dir/rejected/` (full events + response kept) and removed from the
queue so one poison event cannot wedge everything behind it.

## Tests

Everything except `sources/windows.py` is unit-tested and runs on Linux:

```bash
cd endpoint_agent
python -m unittest discover -s tests -t . -v
```

The backend repo also carries a cross-checking contract test,
`apps/endpoints/tests_agent_payload_contract.py`, which pushes this
package's sample payload fixtures through the real ingest endpoint.

## Manual verification on Windows

`sources/windows.py` (the `win32evtlog` query/render calls) cannot run
on the Linux dev box. On a real Windows host:

1. **Enable the audit policy** (admin cmd):
   ```
   auditpol /set /subcategory:"Process Creation" /success:enable
   ```
   Optionally enable *Administrative Templates > System > Audit Process
   Creation > Include command line in process creation events* so 4688
   carries `CommandLine` (the filters work without it, less precisely).
2. **Enable PowerShell script-block logging**: *Administrative Templates
   > Windows Components > Windows PowerShell > Turn on PowerShell
   Script Block Logging*, or set
   `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1`.
3. `pip install pywin32`, create `config.toml`, run
   `python -m aegis_agent run --config config.toml --dry-run`.
4. Launch a few processes (`whoami /priv`, `ipconfig`) and run a short
   PowerShell one-liner. Confirm the log shows: the 4688/4104 events
   read, the expected `svchost`/`conhost` noise `filtered ...`, and the
   rest formatted as ingest items.
5. Drop `--dry-run` and confirm `EndpointEvent` rows appear in the
   backend (Django admin) and the endpoint's `last_seen` updates.
6. Kill the process mid-cycle and restart; confirm no duplicate rows and
   no gap (bookmark + spool resume).
