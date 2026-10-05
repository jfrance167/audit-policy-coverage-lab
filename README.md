# Offline audit-policy prerequisite lab

Explain why enabled audit policy does not prove that a file read will reach an alert. This local Python tool evaluates **supplied declarations**, using the File System successful-auditing requirement for Windows event 4663. Every report keeps **effective coverage unknown**.

The tool reads explicit normalized JSON and produces deterministic JSON or Markdown with a fixed analysis clock. It never queries Windows policy, registry or event logs; it has no network, service, elevation or policy-change functionality. All bundled fixtures are synthetic.

## Run and learn

Python 3.10+ and the standard library are sufficient for the tool. Verification was performed on Python 3.13.7 on Windows; other versions/platforms were not tested. From this directory:

```powershell
python audit_coverage.py fixtures/enabled.json --as-of 2026-10-05T12:00:00Z --format markdown
python audit_coverage.py fixtures/disabled.json --as-of 2026-10-05T12:00:00Z
python audit_coverage.py fixtures/all-declared.json --as-of 2026-10-05T12:00:00Z
python audit_coverage.py fixtures/per-user.json --as-of 2026-10-05T12:00:00Z
```

Create a new report using `--output report.json`. Its parent directory must already exist and support hard links. Existing files, input aliases, and dangling output symlinks are refused. Omit `--output` to print the report; default format is JSON. Without `--as-of`, the UTC clock is used. The captured timestamp is a declaration, not independently verified evidence.

| Synthetic case | System success setting | Context | Effective coverage |
|---|---|---|---|
| enabled.json | declared_policy_present | all unknown | unknown |
| disabled.json | declared_policy_gap | all unknown | unknown |
| missing.json | unknown | all unknown | unknown |
| per-user.json | unknown | all unknown | unknown |
| all-declared.json | declared_policy_present | declared_present, unverified | unknown |

Optional exercise: set `matching_sacl` to false in a copy of all-declared.json. Policy remains declared enabled, while the matching SACL prerequisite becomes a declared gap. An actual alert would still need independent observation.

## Contract

See [fixtures/enabled.json](fixtures/enabled.json) for the minimum shape.

- `schema_version`: integer 1 (boolean and float rejected).
- `source_kind`: `synthetic` or `sanitized`; the latter is a user assertion, not a sanitization guarantee.
- `label`: nonempty neutral string; omit hostnames, usernames and private operational data.
- `captured_at`: `YYYY-MM-DDTHH:MM:SS[.ffffff]Z` or explicit `±HH:MM` timezone. Offset hours 0–23, minutes 0–59; invalid calendar times rejected.
- `scope`: `system` or `per_user`. A per-user snapshot cannot establish the system requirement. No per-user inclusion/exclusion numeric flags are interpreted.
- `subcategories`: at most 128 objects with `guid`, `success`, `failure`; optional `display_name`. GUIDs accept braces/case but normalize to lowercase without braces. Settings must be true, false or null. Display names never establish identity.
- Optional `declarations`: only `per_user_context`, `gpo_context`, `audit_options_context`, `matching_sacl`, `security_log_access`, `retention`, `collector_health`, each boolean or null. Context true means the supplier declares the relevant context resolved/present; it does not mean this tool has resolved policy precedence or verified the prerequisite. Missing/null stays unknown; false is a declared gap.

Unknown fields, duplicate JSON keys and duplicate canonical GUIDs are rejected. Unknown GUIDs are counted as unmodeled, never silently treated as modeled or disabled. Failure auditing does not satisfy the successful-use profile. No aggregate compliance score is calculated.

Freshness is `future` for negative age, `stale` for age greater than 24 hours, otherwise `current`. These labels apply only to supplied timestamps relative to the analysis clock. Policy statuses continue to describe the supplied settings, including for future/stale inputs; they never establish current host configuration.

Resource limits: 262,144 raw bytes, JSON nesting 12, numeric token 32 characters, 128 subcategories, 512 Unicode scalar characters per string (including keys), and 1,048,576 output bytes. Strict UTF-8, no BOM; invalid surrogates, NaN/Infinity and overflowing floating-point numbers rejected. Input is read with a one-byte overflow probe; nesting/numeric limits apply before JSON decoding. Controls and Unicode formatting characters are removed from presented labels; Markdown punctuation is encoded. Do not embed raw JSON reports directly into HTML.

## Architecture and reusable interfaces

`read_snapshot(path)` bounds bytes and returns validated data plus the SHA-256 of exactly those bytes. `parse_snapshot(bytes)` is the data-only schema boundary. `evaluate(validated_snapshot, source_hash, now=aware_datetime)` is a pure evaluator. `render(report, "json"|"markdown")` returns bounded UTF-8 bytes. `write_report(new_path, bytes, input_path=...)` publishes exclusively. Treat these APIs as operating on validated/trusted internal objects after the parser; CLI validates all input.

```text
Explicit JSON bytes -> predecode bounds -> strict schema -> GUID evaluation
                           |                       |
                       source hash           declared prerequisites
                                                   |
                                       bounded JSON/Markdown report
```

The initial profile `file-system-success-4663/v1` uses GUID `0cce921d-69ae-11d9-bed3-505054503030`. [Microsoft MS-GPAC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/65a60bda-c99e-45f0-b727-f681dbe22035) confirms the mapping. [Audit File System](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-file-system) and [event 4663](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663) explain the matching SACL/account/access prerequisites. Sources were reviewed October 5, 2026; research details and alternatives are in [PLAN.md](PLAN.md).

## Output safety and limitations

Reports are fully serialized before file creation. A sibling temporary file is written/flushed, then published through an exclusive hard link. Failure before publication cannot replace a destination or expose a partial report. Cleanup failure after publication returns exit 3 with an explicit complete-report warning; the complete report and temporary link may remain. Cleanup failure before publication returns 2 and reports that no report was published. No recursive cleanup is performed.

Exit 0: completed. Exit 2: rejected input/arguments or filesystem failure. Exit 3: complete report exists but temporary cleanup failed. Filesystem error details are redacted from CLI output. A crash can leave a temporary file; directory-entry durability across power loss is not guaranteed. Use a trusted local directory and regular local input file. Hostile concurrent directory replacement, special devices/pipes, filesystem faults and untrusted Python/runtime/workspace modification are outside this lab's protection model. Hard links require filesystem support and may be blocked by the app sandbox; stdout remains available.

Hashing identifies input bytes without authenticating their claims. The tool cannot observe effective GPO/per-user/options precedence, real SACLs, the account/access operation, Security-log visibility/retention, or collector delivery. CSV adapters, additional profiles and live collection are deferred. The separate [Windows Canary](https://github.com/jfrance167/windows-canary) fixture tests do not establish its still-unverified elevated live detection.

## Verify

```powershell
python -m unittest discover -s tests -v
python verify.py
```

`verify.py` also uses the already installed Bandit module (1.9.4 in this run). It never installs dependencies. It captures test output, syntax checks, ten fixed-clock demos, Bandit output, exit codes and source hashes in a fresh ignored `verification-runs/` directory. Run only from a trusted checkout: this verification helper executes local tests/scripts, unlike the data-only analyzer.

Publication review on October 5: 44/44 tests in normal and optimized Python, three Python syntax checks, ten demos and Bandit exit 0 with zero findings/errors. Two stdout failure cases were fixed before commit. See [VERIFICATION.md](VERIFICATION.md) for exact evidence and [ECC_REVIEW.md](ECC_REVIEW.md) for self-review corrections and narrow false-positive suppressions. Stdout is not transactional: failed writes/encoding/flush can leave partial output and now return exit 2.

Jake authorized a separate private GitHub repository. Pinned test/Bandit and CodeQL workflows are prepared, with dependency-update configuration. Hosted workflows remain disabled until included-usage limits and private CodeQL eligibility are verified; no hosted passes claimed. No paid features or visibility changes activated. Runtime is stdlib-only; optional Bandit development version is pinned, transitive development dependencies are not hash-locked. Local STATE and full evidence output are excluded from commits.

## License and assistance

MIT, Copyright 2026 Jake Franciosa. No upstream source or fixtures were copied. AuditPolicyDsc was inspected as an alternative and not adopted; source/license/maintenance uncertainties are recorded in PLAN.md. Codex assisted with implementation, documentation, testing and self-review. Earlier local/free drafting attempts were unsuitable or unsuccessful; no new worker/provider calls or paid fallback were made for this implementation. No independent code review is claimed.
