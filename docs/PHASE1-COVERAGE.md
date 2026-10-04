# Phase 1 — reference roadmap coverage

The supplied four-phase drawing defines the scope. This implementation targets the first column and the supporting security foundations, not the runtime scanning, auto-fix PRs, security gates or enterprise graph features in later phases.

| Phase 1 feature | Implementation | Verification / deployment boundary |
|---|---|---|
| GitHub OAuth / repository connection | OAuth state validation, encrypted token, paginated repository picker and URL connection | Needs configured OAuth app for live login |
| Repository metadata and branches | Owner, visibility, language, default branch, selected scan branch, commit and last-scan details | Branch access validated with GitHub before enqueueing |
| Technology stack detection | Manifests, imports, language extensions, environment variable names and deployment configuration | Backend fixture checks |
| Basic application graph | React Flow map with zoom, pan, node inspection and evidence; server produces inferred nodes and edges | Build checked; browser visual testing unavailable |
| Code scan | Local Semgrep rule pack | Prior real fixture test passed; limited rule coverage |
| Secrets scan | Gitleaks bounded Git history with full credential redaction | Prior real fixture test passed |
| Dependency vulnerability scan | OSV exact-version advisory lookup, severity, advisory identifiers, fixed-version candidates | Missing/unpinned inputs and query errors mark coverage partial |
| Basic auth / authorization checks | JWT verification, client service-role patterns, admin guards and ownership heuristics | Conservative wording; fixture tests |
| Deployment readiness | Normalized findings, deduplication, severity/confidence/context weighting and decision | Incomplete coverage withholds score; manual triage cannot change scan verdict |
| Findings dashboard | Severity, engine, priority and text filters; detail expansion, evidence, impact, explanation and fix instructions | Domain logic checks; actual service requires backend |
| Scan history | Stored assessments, snapshot navigation, new/resolved differences and previous score | Comparisons use the same branch; partial scans do not claim resolutions |
| Animated frontend | Violet Dusk colours, moving panel, animated flow edges, counters, scroll reveals and hover transitions | Reduced-motion preference respected |
| Secure platform foundations | Tenant isolation, encrypted OAuth token, exact Origin checks, limits, audit records, isolated temporary sources, cleanup and redaction | API tests; full deployment acceptance remains required |
| Report output | JSON export, optional private S3 report storage, optional constrained AI explanations | External services require user credentials |

## Palette placement

- `#502D55`: active navigation, graph roots and violet surfaces.
- `#935073`: primary actions, flowing edges and mauve highlights.
- `#F6DBC0`: important headings, score rings, icons and selected details.
- `#F8F4E9`: primary text and readable foregrounds.
- Darkened violet backgrounds provide contrast. Red, amber and green remain semantic issue/status colours.

## Honest operating state

The hosted preview is a clearly labelled sample workspace. GitHub upload is separate from application GitHub OAuth: a successful source push does not configure user login or run scans. Full local deployment is available through the frontend, API, worker, PostgreSQL and Redis Compose services once `.env` is configured. No live GitHub OAuth or Docker end-to-end test has been claimed.

## 4 October follow-up

Implemented stale-job reconciliation, API/worker service diagnostics, same-origin HTTPS Compose deployment, startup health dependencies, locked backend dependencies, automatic checks, and broader OAuth/API/worker persistence tests. The workflow test covers connection → scan → stored report → manual triage → rescan/diff and failed scanner coverage with controlled external adapters. It is not a live GitHub acceptance test.

Phase 1 **cannot yet be marked live-complete**. Before acceptance:

- Configure the owning GitHub OAuth app and deploy the API, PostgreSQL, Redis, worker, scheduler and HTTPS frontend.
- Run preflight, sign in through GitHub, and select a real repository/branch.
- Run all four real engines; inspect coverage, masked evidence, inferred stack/map, commit and readiness.
- Make a known fixture fix in a test repository, rescan that branch, and confirm persisted new/resolved comparisons.
- Confirm tenant isolation, sign-out, unavailable-worker behavior and reload/reconnect behavior on the deployed application.

The browser QA capability and Docker daemon are unavailable in the authoring environment. The preview remains sample mode; no fabricated live result is substituted for these checks.
