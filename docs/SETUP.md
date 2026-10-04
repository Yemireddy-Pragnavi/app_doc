# Setup and deployment

## Authentication

Create a GitHub OAuth App in the owning account’s developer settings. Configure the callback to the public HTTPS API origin plus `/api/auth/callback`, and the homepage to your frontend origin. Set `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_CALLBACK_URL`, `FRONTEND_URL`, `SESSION_SECRET` and `TOKEN_ENCRYPTION_KEY` in the backend environment.

OAuth’s `repo` scope is broader than read-only permissions. This application only reads repositories; the GitHub scope itself permits more. For strictly read-only installation permissions and short-lived installation tokens, replace this OAuth repository access with a GitHub App before wider distribution. `github_installations` currently records an OAuth connection, not a GitHub App installation.

Put frontend and API on the same registrable domain (for example app.example.com and api.example.com), with HTTPS and `COOKIE_SECURE=true`. The session uses HttpOnly, Secure, SameSite=Lax cookies. Unrelated frontend/API domains are intentionally unsupported by this cookie configuration. Never loosen CSRF controls to work around deployment topology. `FRONTEND_URL` must match the exact browser origin with no trailing slash.

`NEXT_PUBLIC_API_URL` is a frontend build-time value. Do not configure a live API in the hosted sample preview until cookie topology and OAuth callback routing have been tested.

## Worker and services

`compose.yaml` runs the Next.js frontend, PostgreSQL, Redis, API and one non-root worker. PostgreSQL and Redis have no published ports. The API is bound to host loopback; terminate TLS through a reverse proxy. Add reverse-proxy request limits, OAuth endpoint rate limiting and operational monitoring before public use.

The worker has a read-only root filesystem, bounded tmpfs, dropped capabilities, process/memory/CPU limits, no Docker socket and one task per child. Sources are fetched over HTTPS from github.com only, with bounded history and no submodules. Source dependencies and build scripts are never installed or executed. Scans have soft/hard time limits; partial engines cannot yield a readiness score.

Repository metadata is checked before enqueueing; expanded source file limits are checked after checkout. The tmpfs bounds clone/disk growth. A force-killed worker can temporarily leave a running database row. The scheduler and API reads mark stale scans failed after the documented 45-minute window; restart the worker container to discard abandoned tmpfs contents.

Current worker isolation is a bounded process and temporary directory within a restricted container, not a fresh VM per tenant. Use one disposable container/microVM per scan and restricted egress for untrusted multi-tenant production workloads. Scanner vulnerabilities remain a residual risk.

Semgrep and Gitleaks versions are pinned in `backend/Dockerfile`. Update through a reviewed build after rule compatibility tests. `backend/requirements.txt` defines supported ranges; the Docker image installs `backend/requirements.lock`.

## Storage and explanation

PostgreSQL stores normalized findings, audit events and reports. `REPORT_BUCKET` enables private S3 storage of normalized JSON only, encrypted with SSE-S3. Set the bucket to block public access and restrict the worker IAM policy to its report prefix. Source archives and raw scanner JSON are not retained.

AI explanations are opt-in. Set `ALLOW_LLM_EXPLANATIONS=true`, `OPENAI_API_KEY`, and an available `OPENAI_MODEL`. Only redacted finding title, severity, engine, description and remediation are sent. Evidence, code, paths, repository names and GitHub tokens are excluded. Scanner output remains the detection source. Failure falls back to deterministic explanation text.

## GitHub delivery

Source repository: https://github.com/Yemireddy-Pragnavi/app_doc

The supplied repository belongs to the connected GitHub account and permits source updates. It replaces the earlier read-only destination. The hosted preview remains at its existing URL.

## Branch scans and comparison

Select a repository from the paginated GitHub list or paste its URL. Choose a branch before scanning. Branch names are validated, GitHub checks current access, and the worker clones the chosen branch. The stored result records the actual commit scanned. The branch may advance between scheduling and cloning; the recorded commit is authoritative.

The branch picker shows the first 100 branches plus the default branch. The repository list is paginated. Scan-history comparisons are only made against the same branch and do not claim issues resolved if either assessment was incomplete.

## Same-origin production deployment

A Docker-capable Linux host and a domain pointing to it are required. The included `compose.production.yaml` adds Caddy HTTPS, keeps the API under `/backend`, and avoids cross-site cookie problems.

1. Copy `.env.example` to `.env` on the deployment host and generate independent database, session and encryption secrets there.
2. Set `APP_DOMAIN` to your hostname, `FRONTEND_URL=https://YOUR_HOST`, `GITHUB_CALLBACK_URL=https://YOUR_HOST/backend/api/auth/callback`, `COOKIE_SECURE=true`, and the GitHub OAuth app credentials. Register that exact callback in GitHub.
3. Set `RUNTIME_ALLOWED_HOSTS` to a comma-separated list of exact staging hostnames you are authorized to assess. An empty value disables runtime scan submissions. The API and worker both enforce this list.
4. Run `docker compose -f compose.yaml -f compose.production.yaml up -d --build`. The production override builds the frontend with `NEXT_PUBLIC_API_URL=/backend`.
5. Run `docker compose exec api python -m app.preflight`. It reports booleans for configuration, database, queue and worker health without printing credentials. `/health` is process liveness; `/ready` is database/queue/auth configuration readiness. Signed-in Settings additionally checks worker responsiveness.
6. Complete the live acceptance steps in [Phase 1 coverage](PHASE1-COVERAGE.md). A successful preflight is not a substitute for OAuth and a real repository scan.

The scheduler reconciles scans left queued/running for more than 45 minutes. API reads also reconcile stale rows so interrupted jobs do not permanently consume quotas. Failed jobs keep branch/target context and remain in history. The retry action is a new scan. Beat requires exactly one scheduler instance. The total window includes time waiting in the queue; use an appropriately sized worker pool.

New runtime tables are additive and are created by API startup before the worker starts. Existing scan tables are unchanged. Back up PostgreSQL before deployment. This project still uses `create_all`; future destructive schema changes require versioned migrations.

The backend Docker image installs the tested package versions from `backend/requirements.lock`. `requirements.txt` documents allowed ranges; regenerate the lock and rerun tests when updating dependencies. Scanner tool versions remain separately pinned in the Dockerfile.

## Phase 2 HTTP baseline

Open **Launch Readiness**, select a saved repository assessment, enter an authorized public HTTPS URL and optionally add five relative API paths. Confirm authorization, start the check, and review persisted findings, response statuses, coverage gaps and a combined verdict. Export produces a JSON report. Paths must be safe to request with GET; the scanner does not determine whether a broken application uses GET for mutations.

Only port 443 is supported. No credentials, query strings, fragments, private DNS addresses, browser execution or automatic redirect traversal. Every DNS result must be globally routable; connections use a validated IP while preserving TLS hostname verification. Headers are inspected without retaining body or cookie values. Up to six unique paths and two requests per path are normally made (hard request budget 18). Socket timeout is five seconds; the runtime task has a 240-second soft / 270-second hard limit. Timeouts, unavailable paths and redirects are explicit coverage gaps, not clean scans. Worker container egress restrictions remain recommended defense in depth.

The combined review references one immutable repository scan. The UI asks the reviewer to confirm that the deployment matches its commit. Basic correlation supports exact Next app/pages API route file paths; dynamic routes, middleware, browser flows and actual exploitability are not verified. The extended review adds isolated browser observation, supported cloud/BaaS declaration rules and bounded route/import risk paths. Live cloud management-plane integration and confirmed exploitability remain outside the supported scope.

## Full runtime review and browser service

The Compose stack now also includes `browser`. Its offline container communicates only through a shared Unix-socket volume, not a TCP port. The API mounts that volume read-only for service liveness diagnostics. Both images initialize the socket directory for UID 10001. The browser service has no database, GitHub or provider credentials and uses Chromium sandboxing plus the included upstream seccomp profile. Configure the deployment host to support unprivileged user namespaces. Browser startup failure is reported as unavailable coverage; never disable its sandbox to obtain a ready verdict.

After deploying, run a fresh repository scan to collect cloud declarations and route/import inventory. In Launch Readiness, enter the exact full commit SHA deployed to staging, retain browser observation, indicate whether cloud/BaaS configuration applies, and add only authorized safe GET paths. Disabling browser observation leaves a coverage gap. Marking cloud configuration not applicable never hides already-detected cloud blockers. A commit match is recorded as the reviewer's declaration, not independently verified provenance.

Configuration review supports explicit unsafe patterns in Supabase migration SQL, Firebase rules/Realtime Database JSON, and S3 CloudFormation JSON. It does not query cloud provider accounts or assume repository declarations equal deployed state. Complex expressions, cloud YAML, dynamic code, aliases and unsupported graph patterns remain disclosed limitations.

CI `stack` starts temporary containers and runs `backend/tests/stack_smoke.py`: actual scanner binaries, an OSV lookup and browser rendering of synthetic HTML through the same broker. The test contacts no user staging site and uses no user OAuth secrets. Containers/volumes are removed after the test. Browser/container CI is distinct from authoring browser QA, which remains unavailable here.
