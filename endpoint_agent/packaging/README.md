# Part 4 -- packaging, Windows service, installer

Turns the `aegis_agent` package into a single `aegis-agent.exe`, wraps it
as an auto-starting Windows service, and ships an Inno Setup installer
whose only two questions are the enrollment token and a display name.

```
packaging/
  entry.py           PyInstaller entry point (routes --as-service -> the SCM dispatcher)
  aegis-agent.spec    PyInstaller build spec  -> dist/aegis-agent.exe
  installer.iss       Inno Setup 6 script     -> Output/AegisFlowAgentSetup.exe
```

The service itself is `aegis_agent/winservice.py`; its stdlib-only,
Linux-tested helpers are in `aegis_agent/service_support.py`.

## What the exe does

| Invocation | Effect |
|---|---|
| `aegis-agent.exe run --config PATH` | the agent loop |
| `aegis-agent.exe write-config --out … --base-url … --token … --display-name …` | write a valid `config.toml` |
| `aegis-agent.exe enroll-check --config PATH` | enroll once; exit 0 only if the backend answered |
| `aegis-agent.exe service --startup auto install` / `service start` / `service stop` / `service remove` | pywin32 service control |
| `aegis-agent.exe --as-service` | what the SCM runs; never called by hand |

## Baked-in settings (edit before a real build)

In `installer.iss`:

- `BackendBaseUrl` -- **currently the placeholder
  `https://aegisflow.example.org`.** Set this to the real backend URL
  once HTTPS is configured on the server. Nothing else about Part 4
  depends on it.
- `InstallDir` -- `C:\Program Files\AegisFlow Agent`
- `DataDir` -- `C:\ProgramData\AegisFlow\agent` (config, spool, log)
- Service name `AegisFlowAgent` (in `winservice.py` and `installer.iss`)

## Build (on Windows)

```bat
cd endpoint_agent
python -m venv build-venv && build-venv\Scripts\activate
pip install pyinstaller pywin32==306
pyinstaller --clean --noconfirm packaging\aegis-agent.spec
:: -> dist\aegis-agent.exe

:: then, with Inno Setup 6 installed:
iscc packaging\installer.iss
:: -> packaging\Output\AegisFlowAgentSetup.exe
```

## Install flow (what the operator sees)

1. UAC prompt (installer needs admin).
2. One page, two fields: **enrollment token** (paste) and **display
   name** (defaults to the computer name).
3. Silent post-install:
   - `write-config` writes `DataDir\config.toml`, then `icacls` locks it
     to `SYSTEM` + `Administrators` (it holds the token).
   - `service --startup auto install` registers `AegisFlowAgent`;
     `sc failure` sets restart-on-crash.
   - `sc start AegisFlowAgent`.
   - `enroll-check` runs against the backend:
     - **connected** -> message box: *"registered as `<name>`"*, and if
       the server auto-suffixed a colliding name, it says so explicitly
       with the effective name.
     - **not connected** -> message box states plainly that the
       connection was **not** confirmed, shows the error, and notes the
       service will keep retrying. The installer never reports success it
       did not observe.

Uninstall stops and removes the service. `DataDir` (spool + logs) is
left in place deliberately.

## Manual verification on a real Windows host

Everything below is **not** covered by the Linux test suite -- same
situation as `sources/windows.py` in Part 2. The Linux tests do cover
`write-config` / `enroll-check` output and exit codes, config-path
resolution, and the interruptible sleep.

1. Build `aegis-agent.exe`; run `aegis-agent.exe --help` and each
   subcommand's `--help`.
2. `aegis-agent.exe write-config ...` by hand; confirm the TOML loads
   (`aegis-agent.exe run --config ... --once --dry-run`).
3. `aegis-agent.exe service --startup auto install`; check `services.msc`
   shows *AegisFlow Endpoint Agent*, Automatic, and that its ImagePath
   ends in `--as-service`.
4. Start it; confirm `DataDir\agent.log` shows enrollment and ticks.
5. **Stop it and time the stop** -- should be well under the SCM's 30 s
   limit (the interruptible sleep is the reason).
6. Reboot; confirm the service comes back up on its own.
7. Run the full installer on a clean VM:
   - a good token -> success box with the right name;
   - a good token whose name collides with an existing endpoint ->
     success box showing the `-2` name;
   - a bad token -> failure box, service still installed and retrying.
8. `sc query AegisFlowAgent`, kill `aegis-agent.exe` from Task Manager,
   confirm `sc failure` restarts it.
9. Uninstall; confirm the service is gone and `DataDir` remains.
