# AegisFlow AI — Migration-Readiness Report

Source tree: `~/caribsecure_live` (the dev tree, on real Postgres). Generated 2026-09-03.
Target: Vincy Connect VPS. Nothing in this report was deployed, restarted, or moved.

---

> ## 2026-09-06 — installed reality now DIVERGES from the `deploy/` drafts
>
> The app has since been moved onto the VincyPros VPS and is **deployed and
> live** at `https://aegisflow.vincypros.com` — but **not** via the committed
> `deploy/aegisflow.service` / `deploy/nginx-aegisflow.conf` drafts. The VPS
> was provisioned with a home-directory layout, and the systemd unit was
> hand-adapted for it. Installed reality vs. the drafts:
>
> | Aspect | Committed draft (`deploy/*`) | Actually installed on the VPS |
> |---|---|---|
> | App directory | `/opt/aegisflow/app` | **`/home/aegisflow/app`** |
> | virtualenv | `/opt/aegisflow/app/venv` | **`/home/aegisflow/venv`** |
> | `.env` | `/opt/aegisflow/app/.env` | `/home/aegisflow/app/.env` |
> | gunicorn bind | unix socket `/run/aegisflow/gunicorn.sock` (`Type=notify`, `RuntimeDirectory`) | **TCP `127.0.0.1:8001`** |
> | `ProtectHome` | `true` (deliberate — forced the `/opt` path) | **`read-only`**, plus `ReadWritePaths=/home/aegisflow/app` |
> | nginx upstream | `upstream … { server unix:/run/aegisflow/gunicorn.sock; }` | `proxy_pass http://127.0.0.1:8001;` |
> | `/opt/aegisflow` | assumed to exist | **does not exist** |
>
> **Source of truth for the running service, for now, is the installed files**,
> not this repo's `deploy/` directory:
> - `/etc/systemd/system/aegisflow.service`
> - `/etc/nginx/sites-available/aegisflow` (symlinked from `sites-enabled/`)
>
> **Tracked follow-on work (NOT done in this session):**
>
> 1. **Deploy-config reconciliation.** Reconcile `deploy/aegisflow.service`,
>    `deploy/nginx-aegisflow.conf`, and sections 6/7/10 of this report with the
>    home-directory layout that is actually running (or make a deliberate
>    decision to re-migrate onto `/opt/aegisflow/app` to match the drafts).
>    Until then, treat everything below describing `/opt/aegisflow/app`, the
>    unix socket, and `ProtectHome=true` as historical draft intent, not the
>    deployed configuration.
>
> 2. **Test infrastructure — `manage.py test` does not run unqualified on this
>    VPS.** The Postgres role `aegisflow` (from `.env`) lacks `CREATEDB`, so the
>    Django test runner cannot create its `test_*` database:
>    `Got an error creating the test database: permission denied to create
>    database`. Additionally, the live `.env` now sets the production HTTPS vars
>    (`DJANGO_SECURE_SSL_REDIRECT=True` etc.), so even against SQLite every view
>    test 301-redirects before reaching the view. Fix one of:
>    - grant `CREATEDB` to a dedicated test role (e.g. `aegisflow_test`) and
>      point the test settings at it, or
>    - add a `config/settings_test.py` that forces SQLite + disables the
>      `SECURE_*` redirects, run via `--settings=config.settings_test`.
>    Interim workaround used on 2026-09-06: run with the DB vars blanked (SQLite
>    fallback) and `DJANGO_SECURE_SSL_REDIRECT=False DJANGO_SESSION_COOKIE_SECURE=False
>    DJANGO_CSRF_COOKIE_SECURE=False` exported inline for the one command.
>
> 3. **`DJANGO_DEBUG` was still `True` in the live `.env` — fixed 2026-09-06.**
>    Despite the checklist below (§ "Non-secret configuration") calling for
>    `False`, the deployed `.env` shipped with `DJANGO_DEBUG=True`, so production
>    error pages (incl. Django's CSRF-403 page) were exposing a full settings /
>    request dump. Now set to `False`; gunicorn reloaded via `kill -HUP` (the
>    `aegisflow` user has no sudo). Verified: generic 404/403/500 pages, a real
>    login succeeds end-to-end, `logs/django-errors.log` online and clean. The
>    other `DJANGO_*` hardening vars (ALLOWED_HOSTS, CSRF_TRUSTED_ORIGINS,
>    SECURE_PROXY_SSL_HEADER, SESSION/CSRF_COOKIE_SECURE, SSL_REDIRECT) were
>    already correct and loaded — no change needed.

---

## 1. Python / Django versions

| Component | Version | Notes |
|---|---|---|
| Python | **3.12.3** | checked-in `venv/` and system `python3` both 3.12.3. Django 6.0 hard-requires ≥ 3.12. |
| Django | **6.0.6** | current 6.0.x patch line |
| Installed packages (`venv`) | `asgiref==3.12.1`, `Django==6.0.6`, `gunicorn==26.0.0`, `packaging==26.3`, `psycopg2-binary==2.9.12`, `sqlparse==0.6.0` | `requirements.txt` pins only Django / psycopg2-binary / gunicorn; the rest are transitive |
| No `anthropic` SDK | — | AI layer calls `api.anthropic.com` directly via stdlib `urllib`; only needs `ANTHROPIC_API_KEY` in env |
| `endpoint_agent/requirements.txt` | `pywin32==306 ; sys_platform == "win32"` | Windows-only; never installs on the Linux VPS, irrelevant to the server |

Target the VPS at **Python 3.12** (Ubuntu 24.04 ships it; older bases need the deadsnakes/PGDG route).

---

## 2. Current Git commit / status

- **HEAD:** `6d033cb` — *Add reverse-proxy deployment config and HTTPS/logging settings* (this session's approved migration-prep commit)
- **Working tree:** clean (`nothing to commit, working tree clean`)
- **History (full):**
  ```
  6d033cb  Add reverse-proxy deployment config and HTTPS/logging settings
  ee2a001  Add Business Mode experience: guided dashboards and simplified navigation
  9905dee  Initial commit: AegisFlow AI backend + Windows Endpoint Analyzer
  ```
- Branch `main`. Repo-local identity `Osreah Bowens <osreahb@gmail.com>`. **No remote — history lives only in this one `.git/`.** Carry `.git/` across in the migration (clone / push / rsync-with-`.git`); do **not** re-init on the VPS.

---

## 3. Database

| Field | Value |
|---|---|
| Engine | `django.db.backends.postgresql` (via `psycopg2-binary`) |
| Server | PostgreSQL **16.15** (Ubuntu 16.15-0ubuntu0.24.04.1) |
| Database name | `caribsecure_live_dev` |
| Database user | `caribsecure_live_dev` |
| Host / port | `localhost` / `5432` |
| Password | set in `.env` as `DATABASE_PASSWORD` — **not reproduced here** |

Selection logic: Postgres is used only when **all five** `DATABASE_*` vars are set; otherwise the app silently falls back to SQLite. All five are set, so Postgres is active.

- A stray `db.sqlite3` (~128 KB, dated Jun 21) is still on disk, gitignored, **unused** — a leftover, not the live store. Safe to leave behind in the migration.
- Live row counts (unchanged by this session): 1 Organization (id 11), 1 User (id 4), 114 IncidentGroup, 221 ParsedAlert, 114 RiskAssessment / GapFinding / ResponsePlaybook, 11 GeneratedReport, etc. This is the "clean, realistic" org-11 dataset.

**VPS requirement:** install PostgreSQL **16.x** (match the major version for a frictionless `pg_dump`/restore). Create the `caribsecure_live_dev` role + database, restore the dump, then `manage.py migrate` (a no-op if the dump is current).

---

## 4. Media / static paths and sizes

| Setting | Path | Size | Tracked? |
|---|---|---|---|
| `STATIC_URL` | `static/` | — | — |
| `STATICFILES_DIRS` | `~/caribsecure_live/static` | 440 KB | in git |
| `STATIC_ROOT` | `~/caribsecure_live/staticfiles` | 2.0 MB | gitignored — **stale (mid-2025); run `collectstatic` on deploy** |
| `PRIVATE_UPLOAD_ROOT` | `~/caribsecure_live/private_uploads` | 232 KB | gitignored (`.gitkeep` only) |
| `PRIVATE_EXPORT_ROOT` | `~/caribsecure_live/private_exports` | 16 KB | gitignored (`.gitkeep` only) |
| `logs/` | `~/caribsecure_live/logs` | 28 KB | gitignored (`.gitkeep` only) |
| `db_backups/` | `~/caribsecure_live/db_backups` | 752 KB | gitignored — includes the pre-cleanup SQL dump |
| `runtime_logs/` | `~/caribsecure_live/runtime_logs` | 12 KB | gitignored |

- **No `MEDIA_ROOT` / `MEDIA_URL`** — not defined at all. User uploads and generated exports use `PRIVATE_UPLOAD_ROOT` / `PRIVATE_EXPORT_ROOT` and are served **only through authenticated Django views**, never off disk. Nginx has no `/media/` block by design.
- `private_uploads/` and `private_exports/` hold real data (232 KB + 16 KB) — **must be transferred** to the VPS, not just recreated empty.

---

## 5. Required environment variables — names only

`config/settings.py` reads `.env` from the project root with a hand-rolled parser (no `python-dotenv`). Real environment variables win over the file.

### Secrets / credentials (values required, not in this report, not in `.env.example`)
- `DJANGO_SECRET_KEY`
- `ANTHROPIC_API_KEY`
- `DATABASE_NAME`
- `DATABASE_USER`
- `DATABASE_PASSWORD`
- `DATABASE_HOST`
- `DATABASE_PORT`

### Non-secret configuration (safe defaults documented in `.env.example`)
- `DJANGO_DEBUG` — set **`False`** on the VPS
- `DJANGO_ALLOWED_HOSTS` — set to `aegisflow.vincypros.com`
- `BRAND_NAME`, `BRAND_TAGLINE`
- `ANTHROPIC_MODEL` (default `claude-sonnet-5`)
- `AI_SANITIZER_ENABLED` (default `True`)
- `AI_RATE_LIMIT_ENABLED` (default `True`)
- `AI_RATE_LIMIT_GLOBAL_PER_HOUR` (default `40`)
- `AI_RATE_LIMIT_ENDPOINT_PER_MINUTE` (default `8`)
- `AI_TRIAGE_INTERACTIVE_RESERVE` (default `15`)
- `PRIVATE_UPLOAD_ROOT` (default `private_uploads`)
- `PRIVATE_EXPORT_ROOT` (default `private_exports`)

### New this session — reverse-proxy / HTTPS hardening (all optional, dev-safe when unset)
- `DJANGO_CSRF_TRUSTED_ORIGINS` — set to `https://aegisflow.vincypros.com` on the VPS
- `DJANGO_SECURE_PROXY_SSL_HEADER` — set `True` behind Nginx
- `DJANGO_SESSION_COOKIE_SECURE` — set `True`
- `DJANGO_CSRF_COOKIE_SECURE` — set `True`
- `DJANGO_SECURE_SSL_REDIRECT` — set `True`
- `DJANGO_SECURE_HSTS_SECONDS` — leave `0` for the initial cutover; raise later
- `DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS` — leave `False` until HSTS proven
- `DJANGO_SECURE_HSTS_PRELOAD` — leave `False`

> `.env` on this box also still contains `OPENAI_API_KEY` — **nothing live reads it** (`OpenAIProvider` is a non-functional scaffold). Do not carry it forward.

---

## 6. Background services

- **App WSGI server:** gunicorn (one process group, `--workers 3`). In this dev tree it is normally run via `manage.py runserver`; the drafted production unit is `deploy/aegisflow.service`.
- **Endpoint-triage job:** `manage.py triage_endpoint_events` — correlates recent endpoint events and AI-triages the flagged clusters. **Scheduled 2026-09-06** via the `aegisflow` *user* crontab (`crontab -l`), `*/10 * * * *`, running `deploy/cron-triage-endpoint-events.sh` (flock-guarded wrapper; output → `logs/triage-endpoint-events.log`). Host cron, not a systemd timer — deliberate (see the script header). `cron` **is** installed and enabled on this box (the earlier "not installed" note is stale). To reinstall the entry: `crontab deploy/aegisflow.crontab` (or add the one line by hand).
- **No Celery / RQ / channels / websockets / message broker.** No `redis`, no `memcached`. Rate limiting is DB-backed against the `AIRun` table specifically to avoid needing a shared cache.
- **PostgreSQL** — local, `postgresql@16-main.service`.

---

## 7. Current launch method

**This dev tree:** `./venv/bin/python manage.py runserver` (port 8000). No process manager for it.

**The separate legacy prod deployment** (`/var/www/caribsecure`, *not* this tree, *not* a git repo, running a ~June snapshot):
- systemd unit `/etc/systemd/system/caribsecure-gunicorn.service` — `User=prett`, `Group=www-data`, `WorkingDirectory=/var/www/caribsecure`, `ExecStart=…/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:8001 config.wsgi:application`. No sandboxing, no socket (TCP 8001).
- Nginx site `/etc/nginx/sites-available/caribsecure` → proxy to `127.0.0.1:8001`, `server_name 136.115.62.107 _;`, static alias `/var/www/caribsecure/staticfiles/`. HTTP only (port 80), no TLS.
- This legacy stack is the thing the VPS move replaces. It has none of `apps/endpoints`, `endpoint_agent`, or the current `ai_core` — ~2.5 months undeployed.

**Drafted production launch (this session, `deploy/`, NOT installed):**
- `deploy/aegisflow.service` — gunicorn `Type=notify`, unix socket `/run/aegisflow/gunicorn.sock` (`RuntimeDirectory=aegisflow`, mode 0750), `User=aegisflow`, `WorkingDirectory=/opt/aegisflow/app`, `After=/Requires=postgresql.service`. Sandboxing: `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, `ProtectHome=true`, `ReadWritePaths=/opt/aegisflow/app`, kernel/cgroup protections.
- `deploy/nginx-aegisflow.conf` — proxy to that socket, `/static/` served off disk from `/opt/aegisflow/app/staticfiles/`, `client_max_body_size 25m`, `server_name aegisflow.vincypros.com`, HTTP-only until `certbot --nginx` slots in the 443 block.

---

## 8. Migrations status

- **53 migrations applied**, all apps. `manage.py migrate --check` exits 0 (nothing pending).
- `manage.py makemigrations --check --dry-run` → **"No changes detected"** (no un-materialized model changes).
- `manage.py check` → **"System check identified no issues (0 silenced)"** (with the new settings).
- Full test suite: **726 tests, all passing** (`manage.py test --noinput`, ~75 s). Custom runner blocks live Anthropic calls.

---

## 9. Hard-coded Google Cloud addresses

**In the `~/caribsecure_live` repo: none.** (`git grep 136.115.62.107` → no match in any tracked file.)

The live GCP VM external IP `136.115.62.107` was swept for across the whole box. It exists in exactly one functional place:

| Location | Transferred? | Notes |
|---|---|---|
| `/etc/nginx/sites-available/caribsecure` line 3 (`server_name 136.115.62.107 _;`) | **No** — system config on the GCP box | Superseded by `deploy/nginx-aegisflow.conf`, whose `server_name` is `aegisflow.vincypros.com` |
| `~/.bash_history`, `~/.claude/history.jsonl` | **No** — shell/tool history | Non-functional; records of past `sed` edits |
| repo tracked files, `.git/config`, `.env`, `private_uploads/`, `private_exports/`, `db_backups/*.sql`, `~/.ssh/` | — | **not present in any of them** |

`.env`'s current `DJANGO_ALLOWED_HOSTS` is `localhost,127.0.0.1` — the IP is **not** in it (bash history shows it was added once and later reverted; the Aug-20 manual `.env` edit that added it was on the legacy `/var/www/caribsecure` prod box, not this tree). On the VPS, `DJANGO_ALLOWED_HOSTS` is set to `aegisflow.vincypros.com`.

**Nothing being carried to the VPS contains the GCP IP.**

### Destination

`aegisflow.vincypros.com` → DNS A record `2.25.155.50` (verified). The IP is only the DNS target — it is written into **no** file: nginx `server_name`, `DJANGO_ALLOWED_HOSTS`, and `DJANGO_CSRF_TRUSTED_ORIGINS` all use the hostname. `deploy/nginx-aegisflow.conf` now carries the real `server_name`; the VPS `.env` gets `DJANGO_ALLOWED_HOSTS=aegisflow.vincypros.com` and `DJANGO_CSRF_TRUSTED_ORIGINS=https://aegisflow.vincypros.com`.

Other GCP-adjacent findings:
- No `*.googleusercontent.com`, no `metadata.google.internal`, no `35.*`/`34.*` literals outside test fixtures.
- The hostname `caribsecure-demo` appears **only** in one synthetic test fixture — `apps/log_intake/fixtures/linux_auth_sample.log` (sample `auth.log` lines). Not a runtime address; harmless, but you may want to scrub the name.
- `README.md:143` hard-codes `cd /home/prett/caribsecure_live` (cosmetic doc path, appears once). Update post-move.
- `endpoint_agent/config.example.toml` and `endpoint_agent/packaging/installer.iss` carry `https://aegisflow.example.org` — an intentional placeholder for the Windows agent installer, **not touched in this deployment session**. It gets set to the real backend URL when the installer is built for pilot deployment (Part 4 packaging), a separate task.

**Outside the repo (system config, will not travel):** the live IP `136.115.62.107` is hard-coded in `/etc/nginx/sites-available/caribsecure` (`server_name`) on the GCP box. That file stays behind; `deploy/nginx-aegisflow.conf` replaces it.

---

## 10. System packages / services required on the VPS

### APT packages
| Package | Purpose |
|---|---|
| `python3.12`, `python3.12-venv`, `python3.12-dev` | app runtime + venv creation |
| `build-essential`, `libpq-dev` | only if building `psycopg2` from source; **not needed** while `psycopg2-binary` stays in `requirements.txt` (keep the binary wheel and you can skip both) |
| `postgresql-16`, `postgresql-client-16` | database (match major 16) |
| `postgresql-contrib` | optional, extension support |
| `nginx` (`nginx-common`) | reverse proxy / TLS termination / static files |
| `certbot`, `python3-certbot-nginx` | Let's Encrypt TLS + auto-renew |
| `git` | to carry the repo with history |
| `cron` | installed + enabled; runs the `triage_endpoint_events` job every 10 min via the `aegisflow` user crontab (`deploy/aegisflow.crontab`) |

No Redis, Memcached, RabbitMQ, Node, or build toolchain for assets (static is pre-built, no bundler).

### systemd services to enable on the VPS
- `postgresql@16-main.service` (or `postgresql.service`)
- `nginx.service`
- `aegisflow.service` (from `deploy/aegisflow.service`, after `daemon-reload`)
- `certbot.timer` (installed with the certbot package; renews automatically)

### VPS provisioning steps not done here (Phase 3)
1. Create service user `aegisflow:aegisflow` (no login shell, home `/opt/aegisflow`).
2. Check out the repo (with `.git/`) to `/opt/aegisflow/app`; build `venv/`; `pip install -r requirements.txt`.
3. Hand-transfer `.env` to `/opt/aegisflow/app/.env`, `0600 aegisflow:aegisflow`, with `DJANGO_DEBUG=False`, `DJANGO_ALLOWED_HOSTS=aegisflow.vincypros.com`, `DJANGO_CSRF_TRUSTED_ORIGINS=https://aegisflow.vincypros.com`, and the `DJANGO_SECURE_*` vars set to production values.
4. Transfer `private_uploads/` and `private_exports/` contents.
5. Create the Postgres role + DB; restore the dump; `manage.py migrate`; `manage.py collectstatic`.
6. Install both `deploy/` files as-is (`server_name aegisflow.vincypros.com` already baked in), then `mkdir -p /var/www/certbot`, confirm DNS resolves, and run `sudo certbot --nginx -d aegisflow.vincypros.com`.
7. `manage.py createuser` for the real login account on the VPS.

---

## Confirmations for this session's change set

- **Exact diff:** `config/settings.py` (+105) and `.env.example` (+22); `deploy/aegisflow.service` and `deploy/nginx-aegisflow.conf` added as-is (drafts from session `209cb9cd`, unchanged). All in commit `6d033cb`.
- **`manage.py check`:** no issues.
- **`manage.py test --noinput`:** 726 passed.
- **No secrets added:** every secret-shaped line in the diff is an empty `KEY=` or a bare variable name. Verified.
- **`.env` still gitignored:** `.gitignore:1` = `.env`; `git ls-files` does not list it; not staged, not committed.
- **No database data changed:** no write was issued to `caribsecure_live_dev`; row counts match the org-11 baseline. The test run used a throwaway test DB, destroyed afterward.
- **`/var/www/caribsecure` not touched:** never referenced by any command; mtime unchanged (Aug 20).
- **DEBUG gate verified:** with `DEBUG=True` (dev + the test run) no `logs/django-errors.log` is created; with `DEBUG=False` the dir + rotating handler come online. The probe artifact was removed.
- **Committed:** `6d033cb` on `main`, working tree clean.

### Not done (per your instructions)
No deploy to VincyPros, no DNS changes, no `.env` edit, no production-service restart, nothing deleted or moved.
