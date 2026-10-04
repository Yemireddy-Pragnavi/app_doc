# Phase 2 — launch readiness and runtime context

## Implemented in the first increment

- Dedicated animated Launch Readiness workspace in the existing Violet Dusk design.
- Tenant-owned runtime jobs tied to a saved repository assessment; exact-host operator allowlist, user authorization acknowledgement, per-user quotas and Origin checks.
- Bounded public HTTPS GET checks for the target and up to five optional routes.
- Header checks for HSTS, CSP/evaluated scripts, framing and MIME sniffing.
- Cookie attribute inspection with no retained names/values, and a controlled untrusted-origin CORS check.
- Persisted route response statuses, coverage gaps, findings, priorities, assessment history and JSON export.
- Exact static Next.js route-path correlation; repository blockers remain blockers and incomplete coverage cannot produce a ready verdict.
- Optional private report-object storage through the existing configured S3 report integration.

## Explicitly not yet implemented

Playwright/headless-browser sessions, authenticated crawling, cloud/BaaS management-plane integrations, comprehensive runtime configuration rules, dynamic-route/call-graph reachability, advanced attack paths and exploitability confirmation. These are the remaining Phase 2 increments. Fix PRs and CI security gates belong to Phase 3.

## Operating state

The hosted preview shows an explicitly labeled sample report. The real runtime worker requires the same external API/Postgres/Redis infrastructure as Phase 1 and the configured target allowlist. No user staging URL has been scanned in this authoring session.

## Verification boundary

Automated tests cover SSRF address checks, TLS hostname/IP pinning, blocked URL forms, redirects, cookie-value omission, CORS classification, coverage-aware verdicts, tenant ownership, quotas and API/worker persistence. External HTTP and scanner dependencies are replaced by controlled fixtures in workflow tests. Live DNS/TLS, a real staging assessment and the full Docker deployment remain deployment acceptance checks.
