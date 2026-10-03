# Setup and deployment

## Authentication

Create a GitHub OAuth App in the owning account’s developer settings. Configure the callback to the public HTTPS API origin plus `/api/auth/callback`, and the homepage to your frontend origin. Set `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_CALLBACK_URL`, `FRONTEND_URL`, `SESSION_SECRET` and `TOKEN_ENCRYPTION_KEY` in the backend environment.

OAuth’s `repo` scope is broader than read-only permissions. This application only reads repositories; the GitHub scope itself permits more. For strictly read-only installation permissions and short-lived installation tokens, replace this OAuth repository access with a GitHub App before wider distribution. `github_installations` currently records an OAuth connection, not a GitHub App installation.

Put frontend and API on the same registrable domain (for example app.example.com and api.example.com), with HTTPS and `COOKIE_SECURE=true`. The session uses HttpOnly, Secure, SameSite=Lax cookies. Unrelated frontend/API domains are intentionally unsupported by this cookie configuration. Never loosen CSRF controls to work around deployment topology. `FRONTEND_URL` must match the exact browser origin with no trailing slash.

`NEXT_PUBLIC_API_URL` is a frontend build-time value. Do not configure a live API in the hosted sample preview until cookie topology and OAuth callback routing have been tested.

## Worker and services

`compose.yaml` runs the Next.js frontend, PostgreSQL, Redis, API and one non-root worker. PostgreSQL and Redis have no published ports. The API is bound to host loopback; terminate TLS through a reverse proxy. Add reverse-proxy request limits, OAuth endpoint rate limiting and operational monitoring before public use.

The worker has a read-only root filesystem, bounded tmpfs, dropped capabilities, process/memory/CPU limits, no Docker socket and one task per child. Sources are fetched over HTTPS from github.com only, with bounded history and no submodules. Source dependencies and build scripts are never installed or executed. Scans have soft/hard time limits; partial engines cannot yield a readiness score.

Repository metadata is checked before enqueueing; expanded source file limits are checked after checkout. The tmpfs bounds clone/disk growth. A force-killed worker can leave a running database row; monitor stale jobs and restart the worker container to discard tmpfs. Automated stale-job reconciliation is a remaining production hardening task.

Current worker isolation is a bounded process and temporary directory within a restricted container, not a fresh VM per tenant. Use one disposable container/microVM per scan and restricted egress for untrusted multi-tenant production workloads. Scanner vulnerabilities remain a residual risk.

Semgrep and Gitleaks versions are pinned in `backend/Dockerfile`. Update through a reviewed build after rule compatibility tests. `backend/requirements.txt` defines supported dependency ranges; a deployed release should produce and retain a tested fully pinned Python lockfile.

## Storage and explanation

PostgreSQL stores normalized findings, audit events and reports. `REPORT_BUCKET` enables private S3 storage of normalized JSON only, encrypted with SSE-S3. Set the bucket to block public access and restrict the worker IAM policy to its report prefix. Source archives and raw scanner JSON are not retained.

AI explanations are opt-in. Set `ALLOW_LLM_EXPLANATIONS=true`, `OPENAI_API_KEY`, and an available `OPENAI_MODEL`. Only redacted finding title, severity, engine, description and remediation are sent. Evidence, code, paths, repository names and GitHub tokens are excluded. Scanner output remains the detection source. Failure falls back to deterministic explanation text.

## GitHub delivery

Source repository: https://github.com/Yemireddy-Pragnavi/app_doc

The supplied repository belongs to the connected GitHub account and permits source updates. It replaces the earlier read-only destination. The hosted preview remains at its existing URL.

## Branch scans and comparison

Select a repository from the paginated GitHub list or paste its URL. Choose a branch before scanning. Branch names are validated, GitHub checks current access, and the worker clones the chosen branch. The stored result records the actual commit scanned. The branch may advance between scheduling and cloning; the recorded commit is authoritative.

The branch picker shows the first 100 branches plus the default branch. The repository list is paginated. Scan-history comparisons are only made against the same branch and do not claim issues resolved if either assessment was incomplete.
