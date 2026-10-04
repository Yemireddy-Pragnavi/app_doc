# Phase 2 — implementation and acceptance scope

The launch-review pipeline now includes every core category in the supplied Phase 2 roadmap, within the supported checks below. This is **implementation coverage**, not a declaration that the deployed product or any scanned application is fully secure.

| Category | Implemented behavior | Boundary |
|---|---|---|
| Staging/preview scan | Authorized public HTTPS target, selected GET routes, persisted jobs/history | One origin, port 443; no redirects, queries or login sessions |
| Runtime configuration | HSTS, enforced CSP header, evaluated scripts, framing, MIME sniffing, cookie attributes, controlled CORS origin probe | Response rules; headers alone cannot establish exploitability |
| Browser behavior | Sandboxed Chromium; insecure password form actions, cross-origin form actions, mixed resources, script-error/resource counts | Stateless observation; no interaction, form submission, stored cookies or screenshots |
| API inspection | Selected route statuses plus browser-request evidence | A 200/401/403 is an observation, not an authorization proof |
| BaaS/cloud review | Explicit Supabase migration patterns, Firebase rules/Realtime Database JSON and S3 CloudFormation JSON | Declarative review only; live provider settings and drift are unverified; unsupported cloud YAML is a coverage gap |
| Reachability/context | Literal and parameterized route matching; bounded JS/TS local-import chains; Python/Express literal route declarations | Inferred links, not whole-program taint analysis or confirmed exploit chains |
| Launch verdict | Immutable Phase 1 baseline + runtime/cloud/browser findings + coverage + reviewer-declared commit match | Incomplete/mismatched coverage cannot produce READY FOR REVIEW; known blockers remain NOT READY |
| Report/artifacts | Must-fix list, potential paths, metadata, gaps, history, JSON export and optional private S3 JSON storage | No raw page content, cookies, credentials or source archives retained |

## Browser isolation

`browser` is a separate, unprivileged, read-only Compose container with **no network interfaces**, no environment credentials, Chromium sandboxing enabled and the upstream Playwright seccomp profile. The scanner worker fetches resources through a temporary Unix-socket broker, using a per-job capability and the same public-IP/TLS checks as HTTP scanning. The broker never forwards browser cookies or arbitrary headers. Only same-origin GETs without queries are served. WebSockets, downloads, service workers, other methods and cross-origin requests are blocked.

Caps: 60 resource fetches, 2 MB per resource, 12 MB total, 45–55 second browser/broker window. The entire runtime task has 240/270 second soft/hard limits. Failed browser startup, missing sandbox support, blocked resources or script errors reduce coverage. No fallback disables isolation. One browser server handles one observation at a time; concurrency remains one per scanner worker.

## Acceptance remains open

Live OAuth/backend hosting has not been provisioned. Neither a user repository nor a user staging deployment has been scanned. The hosted preview remains labeled sample data. GitHub Actions includes a full container fixture check for real Semgrep, Gitleaks, OSV, PostgreSQL, Redis, Celery and isolated Chromium; its result must be reviewed separately from unit tests. Provider management-plane integrations and authenticated/browser-interaction crawling are outside this supported first-release scope; they must not be represented as completed live audits.

## Rule references

- https://playwright.dev/python/docs/docker
- https://playwright.dev/python/docs/api/class-browsercontext
- https://supabase.com/docs/guides/database/postgres/row-level-security
- https://firebase.google.com/docs/rules/insecure-rules
- https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-publicaccessblockconfiguration.html
