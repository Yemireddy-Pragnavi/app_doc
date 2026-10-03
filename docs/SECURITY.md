# Security model and limitations

## Boundaries implemented

- GitHub-only validated URLs; no arbitrary host cloning or shell evaluation.
- Signed expiring OAuth state tied to an HttpOnly nonce cookie.
- Encrypted OAuth tokens using a deployment-provided Fernet key; database stores only hashed session identifiers.
- Ownership checks on repository, scan, findings, diagnosis, report, history and triage endpoints.
- Origin checks on authenticated state-changing operations, with an exact CORS allowlist.
- Tenant scan quotas (two active / ten per hour) and explanation quotas.
- Bounded clone depth, file count, source size, subprocess output and execution duration.
- Scanner subprocesses receive a minimal environment without database, OAuth, or LLM secrets. Git authentication is passed only to the clone subprocess and not persisted in remote URLs.
- Gitleaks fully redacts credentials; raw code evidence is intentionally omitted. Potential auth weaknesses retain uncertainty.
- Missing tools, parse failures, unsupported dependency formats and failed advisory queries produce incomplete coverage, not a clean bill of health.
- Manual “fixed” records are unverified. Historical scan scores are immutable; rerun to verify remediation.

## Coverage

The local Semgrep pack covers representative eval, SQL interpolation, shell execution, HTML insertion, pickle, weak hashing, URL fetch, file-path and redirect patterns. It is intentionally limited and does not replace a maintained comprehensive rule pack. Gitleaks scans at most the cloned 100 commits. Earlier history is not covered.

OSV analyzes exact versions from npm v2/v3 lockfiles, pinned requirements, Poetry, common pnpm and Yarn locks. Unsupported or unpinned manifests mark dependency coverage partial. Runtime reachability is not established; dev/production dependency classification is unknown where the lock format does not reliably provide it. Fixed releases are advisory-listed candidates, not a guarantee that any listed version is compatible with the application.

Auth checks are local-file heuristics. Middleware, dynamic routing and cross-file checks can create false positives and false negatives. Application relationships are inferred from manifests and basic file evidence, not runtime tracing.

## Risk model

`risk = severity_weight × confidence × estimated_reachability × estimated_exposure × estimated_context`

Severity weights: Critical 10, High 7, Medium 4, Low 1. Reachability is currently estimated at 0.8. API/client/public paths receive exposure factor 1.2; other paths 1.0. Confirmed dev dependencies receive context factor 0.7. UI and report label these factors as estimates.

Must Fix: risk >=4.7 or a high-confidence critical. Fix Soon: >=2.5. Review: >=1. Informational: below 1. Score is `max(0, round(100 - sum(risk × 2.5)))`, only if all required engines complete. Any Must Fix finding produces NOT READY regardless of numeric score. Partial coverage produces INCOMPLETE with no score.

## Before public production

Use disposable per-scan isolation, egress allowlisting, scanner image patching, database migrations and backups, key rotation, token revocation, stale-task reconciliation, audit retention and operational alerting. OAuth repository permission scope must be communicated honestly. The supplied setup is an MVP and still needs live OAuth and full container end-to-end acceptance testing.
