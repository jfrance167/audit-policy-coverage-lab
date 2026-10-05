# Offline Windows audit-policy coverage lab — proposed plan

October 5, 2026. Tier 2, with extra review for untrusted input and misleading security conclusions. All three local implementation stages approved by the authorized coordinator; see STATE.md.

## Authority and success criteria

Verified direct human messages in coordinator chat 01a10a45-1a24-78b3-9cef-7c461a966d26 authorize that chat to approve further work and research successors after completed labs. The coordinator approved this concrete plan and all three stages, with no live policy changes, real log collection, services or elevation. Stop new dispatch at 08:00 Eastern October 6.

Teach why a quiet event log does not prove a quiet host. Analyze supplied synthetic/sanitized policy snapshots and explain which declared audit prerequisites are present, absent or unknown. Success means deterministic, traceable prerequisite reports that never claim successful event collection or effective host compliance.

Windows Canary remains separately complete for fixture scope: ECC self-review fixed two validation bugs; 38 tests pass on each PowerShell runtime. Its elevated/live SACL and Security-log verification is still unavailable. This successor does not replace or resolve that gap.

## Existing work and candidate selection

Read Windows Event Collection and Investigation vault evidence, Windows Process Creation Event 4688 Evidence, the local windows-event-log-investigation README/analyzer structure, and current Canary records. Existing investigation work collects and analyzes events; it documents missing Security-channel access and a missing harmless marker. It does not provide an offline declared-policy prerequisite evaluator. No dedicated matching audit-policy project was found in the bounded local filename/vault searches performed. This was not an exhaustive search.

Two successor candidates considered:

1. **Offline policy prerequisite coverage**: evaluate GUID-keyed declared audit settings and explicitly supplied supplementary prerequisites. Distinct from the event analyzer; works without live host privileges. Recommended.
2. **Offline event-channel visibility replay**: compare expected synthetic events against supplied channel samples. Feasible, but overlaps the existing investigation lab and risks turning absence in a sample into an unsupported configuration conclusion. Keep its lessons as explanatory fixtures rather than create a second event analyzer.

## Upstream/reuse assessment

[dsccommunity/AuditPolicyDsc](https://github.com/dsccommunity/AuditPolicyDsc) was found through the connected GitHub integration. Public API reads confirmed non-archived status, dev default branch and pushed_at 2019-02-13; these metadata are maintenance evidence, not proof of current incompatibility. README documents version 1.4.0.0, resources, GUID-based locale workarounds and AppVeyor badges. Unit tests/AppVeyor configuration are present; current CI success was not established.

Inspected its actual [CSV resource](https://github.com/dsccommunity/AuditPolicyDsc/blob/dev/DSCResources/MSFT_AuditPolicyCsv/MSFT_AuditPolicyCsv.psm1) and [unit CSV](https://github.com/dsccommunity/AuditPolicyDsc/blob/dev/Tests/Unit/audit.csv). The resource's Get operation exports live policy; Set restores policy; Test invokes live backup for comparison. That operational design exceeds this offline-only scope. It also conditionally uses Security cmdlets or auditpol, adding host/platform coupling we do not need.

The MIT license was read and names Microsoft Corporation; preserve the notice if any source/fixture is copied. Public issue reports [59](https://github.com/dsccommunity/AuditPolicyDsc/issues/59) and [58](https://github.com/dsccommunity/AuditPolicyDsc/issues/58) concern combined success/failure settings and paths containing spaces. These were not reproduced. No dependency vulnerability audit or Scorecard run was performed.

Source evidence saved as inert .txt files under ../.private/audit-policy-research-20261005/. API blob IDs: README 456a657543556e82d9b11aab76ec3cad836d234d; CSV resource 16acd57ec1abf7d0c51bceb34e9d76e7ae7b3ffc; CSV fixture df5e294b04a5212aff822a144ac69cc8c2bc19ca. These identify read blobs, not a fully pinned/verified repository checkout. No upstream code was executed or imported.

Recommendation: **build** a small Python standard-library offline evaluator, borrowing concepts and citing primary docs, with no upstream runtime dependency or copied fixture content. Adopt the GUID lesson; avoid importing the DSC execution path. Existing analyzer supplies conventions for bounded input, deterministic reports and explicit evidence gaps; keep its source untouched.

## Input approaches and research limits

Approach A: directly parse auditpol /backup or /get /r CSV. Useful future interoperability, but the commands differ in content; backup includes system policy, per-user policy and options. The inspected English fixture includes option/global-SACL rows with blank GUIDs. Locale-sensitive headings, policy-target names and setting labels cannot be assumed invariant. One old English fixture is insufficient to claim current Windows/version/locale coverage. Reject this as the initial ingestion contract.

Approach B: a **versioned normalized JSON snapshot**, generated synthetically or manually sanitized/normalized from an authorized export outside the tool. Key entries by canonical GUID, use explicit Boolean-or-null success/failure values, and declare scope/source kind. Human normalization is a provenance limitation; it is not automatically verified against a host. Recommended first version.

Microsoft documents that auditpol can select categories/subcategories by GUID; report format includes policy target and inclusion/exclusion fields. Native AUDIT_POLICY_INFORMATION flags have function-dependent meanings (success 1, failure 2, none 4); the upstream backup fixture uses Setting Value 0 for No Auditing. Do not reuse one encoding as the other or translate numeric values without a separately validated adapter. A public SDK-header retrieval failed, so no additional SDK GUID mapping was verified from that attempt.

## Scope and architecture

- Python CLI reads only explicitly supplied bounded UTF-8 JSON files; no subprocesses, network, Win32 calls, registry access or implicit host discovery.
- Input contract: schema_version, synthetic/sanitized source_kind, neutral snapshot label, captured_at with timezone, explicit system/per_user scope, and a bounded list of subcategory GUIDs with success/failure true/false/null. Display names are optional untrusted labels, never identifiers. Reject duplicate GUIDs, duplicate JSON object keys, invalid types, malformed timestamps, unsupported schema/scope and contradictory data. Missing known GUID means unknown, not disabled.
- Initial requirement profile: File System successful reads for Canary, tied to 4663 and verified File System GUID {0cce921d-69ae-11d9-bed3-505054503030}. Separate optional declarations represent matching file SACLs, log access, retention and collector health. Missing supplementary evidence stays unknown. Do not infer it from system policy. Expand other event profiles only after checking their primary mapping/prerequisites.
- Per-user snapshots are recognized as out-of-scope for effective system coverage and cannot satisfy a system requirement. Explicitly mark unknown/unmodeled per-user overrides, inherited/GPO effects and audit-option precedence.
- Pure evaluator produces declared_policy_present, declared_policy_gap, or unknown, with input location, requirement and reason. Never produce a global compliant/protected/detection_works verdict.
- JSON and Markdown outputs include source kind, snapshot age, profile version, source hash, counts and limitations. Escape/control-sanitize report text; no raw host/user fields are required. Output files are explicit, exclusive-create by default; refuse overwriting input files. No auto-fixes.

The learning demo varies policy and supplementary declarations to show that enabled system policy can still leave SACL, access or retention unknown. Reports evaluate supplied declarations only.

## Threat model and risks

An input can be malformed, hostile, incomplete, stale or falsely sanitized. Prevent code execution, path/output clobbering, resource exhaustion and report-format injection with data-only parsing, size/count/string bounds, safe outputs and strict schema validation. Protect private exports by keeping collection/import outside this scope and publishing only synthetic fixtures. Hashes bind a report to an input; they do not authenticate the snapshot or prove real configuration. Missing/per-user/effective-policy context cannot be silently upgraded to positive coverage.

## Stages and definitions of done

1. **Contract and provenance**: README/profile/spec, bounded schema parser and synthetic fixtures. Done when duplicate fields/IDs, invalid GUIDs/types, unknown scope/version, malformed/oversized input and same input/output paths fail safely.
2. **Evaluator and reports**: deterministic pure prerequisite evaluation plus JSON/Markdown CLI. Done when missing/false/true/null are distinguished, supplementary unknowns remain visible, translated labels cannot alter results, per-user data cannot satisfy system requirements and report text cannot inject markup/control commands.
3. **Evidence and portfolio handoff**: demo matrices, unittest suite, fixed-clock stale-snapshot cases, output failure/overwrite tests, ECC self-review and exact verification records; README, MIT license, attribution, AI disclosure, STATE/DECISIONS/LEARNING and relevant vault milestone. Done when offline tests pass and limits are explicit. No universal coverage score or host-security assurance claim.

Implementation can use installed Python and standard library unittest; no dependency, billing, provider signup, live collection or elevated action is needed. Raw CSV support is deferred and needs real sanitized fixtures across the precise claimed formats/locales, official field semantics, and a separate reviewed plan. Publication remains outside scope.

## Primary sources and tool record

Reviewed October 5, 2026:

- [Microsoft auditpol get](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-get): GUID/name selectors and CSV report context.
- [Microsoft auditpol backup](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-backup): system/per-user/options content and privilege boundary.
- [Microsoft AUDIT_POLICY_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-audit_policy_information): function-dependent flag semantics.
- [Microsoft MS-GPAC example](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/65a60bda-c99e-45f0-b727-f681dbe22035): confirms the File System GUID and illustrates distinct per-user inclusion/exclusion semantics. The initial normalized profile uses this GUID; raw CSV numeric values are not interpreted.
- [Microsoft Audit File System](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-file-system) and [event 4663](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663): SACL and successful-use prerequisites.

GitHub search/issues worked; connector file fetches and Firecrawl failed. Web documentation plus explicit read-only public GitHub API access supplied the inspected evidence. Raw source fetches partly failed; no false claim of tool success. No worker was invoked for this research/security-judgment plan: earlier local output was inadequate and the deliberate verified-free OpenRouter draft failed; no further attempts or paid fallback. Laya classification would not resolve a relevant uncertainty.
