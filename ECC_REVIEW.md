# ECC self-review â€” October 5, 2026

Used the installed ecc-code-review entry point and pinned reviewer checklist. The implementing Codex agent reviewed this project's complete new analyzer, CLI, callers, synthetic fixtures, 42 tests, verification helper and documentation. This is not an independent review or a claim that the full native ECC plugin is installed.

Reviewed trust boundaries: bytes/schema, canonical identity, time interpretation, pure analysis, formatting, filesystem publication, error reporting, local verification subprocesses and dependencies. Parent tracked diffs were inspected for separation and left unchanged; no staging/commits performed.

| Severity | Location in final source | Trigger and evidence | Correction |
|---|---|---|---|
| MEDIUM | audit_coverage.py:41 | Before the fix, `parse_time('2026-10-05T12:00:00+00:60')` returned 11:00 UTC instead of rejecting an invalid minute field, potentially distorting freshness. Directly reproduced. | Explicit timezone hour/minute bounds before datetime parsing; invalid positive/negative minute regression cases pass. |
| LOW | audit_coverage.py:254 and :302 | If exclusive publication succeeds but temporary unlink fails, the original generic failure path returned exit 2 with no indication that a complete report exists. Reproduced through an injected unlink PermissionError. | Track publication state; explicit cleanup exception and exit 3 after publication, exit 2 before it. Both failure states tested. |

Bandit first reported four LOW subprocess advisories in verify.py (original evidence in verification-runs/20261005T050505944237Z/bandit.json). Manual call tracing confirmed fixed selected local Python, fixed modules/scripts, fixture path as a data argument, trusted workspace and no shell. Narrow `nosec B404` at verify.py:6 and `nosec B603` at :26, :34, :40 include explanations. No broad rule exclusions. These are reviewed false positives within the verification helper's trusted-checkout model; the analyzer itself imports no subprocess or networking modules and has no suppressions.

Re-review after fixes: no outstanding actionable findings reported within the documented model. Recommendation: complete for approved offline/local scope. Limits include no independent review, no CodeQL/remote CI, no live Windows auditing, and no hostile-directory/crash durability assurance. Data-only semantics do not authenticate snapshots. No merge/deployment/publication authorization follows from this verdict.

Final validation: 42/42 tests, three Python AST checks, ten demos, Bandit exit 0; all eight recorded code/fixture hashes match current files. See VERIFICATION.md. Scoped credential-pattern checks found zero hits in code/test/fixture files; this was not a comprehensive secrets audit of unrelated history.

## Private publication review

ECC publication self-review (2026-10-05): fixed MEDIUM ASCII stdout encoding failure and LOW short-write/flush failure at audit_coverage.py:301-309. Both now return redacted exit 2 rather than traceback or false success. Regression checks pass: 44 normal and 44 optimized tests, three AST checks, ten demos, Bandit exit 0 with zero findings/errors. Current evidence: verification-runs/20261005T161233856234Z/report.json plus optimized-review logs in that directory. No outstanding actionable finding within the bounded offline model. Reviewed pinned CI is prepared but Actions/CodeQL have not run. Private publication explicitly authorized by Jake.

This is an ECC self-review, not an independent review. Existing workflow patterns were reused under Ponytail; no tests or security guards were removed. Small private publication/security edits stayed with Codex as unsuitable worker judgment. Raw evidence and local operational state are excluded from Git.
