# Verification — October 5, 2026

Original final run: `verification-runs/20261005T050543583892Z/report.json`. Superseded for current code by the publication review run below; retained as historical evidence.

Command: installed Python 3.13.7 invoked `verify.py` from this directory. Wrapper exit 0. The helper records exact commands, versions, exit codes and eight SHA-256 hashes for three Python source/test files and five JSON fixtures. Full test stdout/stderr, ten generated demo reports and Bandit JSON/stderr are stored beside the report. All hashes were rechecked against current files and matched after documentation completion; documentation files are not included in these code hashes.

| Check | Result | Evidence |
|---|---|---|
| Python AST parse | PASS | three files, report.json syntax record |
| unittest behavioral suite | PASS | 42 tests, exit 0, tests.stderr.txt |
| Five cases × JSON/Markdown, fixed clock | PASS | ten commands, all exit 0, report.json demos and outputs |
| Installed Bandit 1.9.4 | PASS | exit 0, zero remaining results, four narrow reviewed verification-helper suppressions |
| Exact code/fixture provenance | PASS | eight current hashes match report.json |
| Scoped credential-pattern check | PASS for scanned patterns | zero private-key/GitHub/AWS patterns in analyzer, tests, verifier and fixtures; not a comprehensive secret audit |
| Live policy/log/SACL behavior | NOT APPLICABLE | explicitly outside this offline lab |
| CodeQL/remote CI | NOT RUN | no standalone owned repository or publication requested |
| Other Python versions/platforms | NOT RUN | support expectation only, not claimed verification |

Tests cover canonical GUID duplicates, duplicate JSON fields, strict types, malformed Unicode/JSON, byte/depth/numeric/count/string limits, nonfinite numbers, missing/false/null settings, localized name spoofing, per-user scope, all-present uncertainty, deterministic clocks, stale/future snapshots, timezone validation, markup/control injection, exclusive publication, input/hardlink aliases, competing creation, flush/link/cleanup failures, no-output invalid input and CLI path redaction.

Initial sandbox invocation failed because the redirected temporary directory denied file writes. Tests now place temporary directories under this workspace. Hard-link creation remained sandbox-blocked; automatic review approved the same offline checks outside the app sandbox, without Windows elevation or host configuration changes. First successful 40-test run is preserved in `20261005T050330025845Z`. The 42-test run with Bandit advisories and wrapper exit 1 is preserved in `20261005T050505944237Z`; no failure evidence was deleted. Initial uncaptured sandbox diagnostics remain in this chat's tool outputs.

The analyzer uses only standard-library imports. Verification is a trusted-code operation and launches local Python checks with explicit argument lists, no shell and bounded waits. Passing tests/static analysis are evidence for this scope, not a proof of security or actual Windows event collection.

## Publication review verification

Current receipt: `verification-runs/20261005T161233856234Z/report.json`, verify.py wrapper exit 0. After stdout corrections: **44/44 tests passed**, three AST checks, ten demos, Bandit exit 0 with zero findings/errors. Additional `python -O -W error -m unittest discover -s tests -v` passed 44/44, exit 0; full output retained in that run's optimized-review stdout/stderr files. Eight current source/fixture hashes match. The earlier 42-test run describes the pre-fix source only.

Repository publication is now explicitly authorized. Pinned hosted workflows are prepared but disabled pending included usage/private licensing verification; CodeQL/hosted checks remain NOT RUN. No real host audit behavior claimed.
