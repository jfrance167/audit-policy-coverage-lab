# Decisions — October 5, 2026

- Build a Python standard-library offline evaluator. AuditPolicyDsc exports/restores live policy and does not fit this boundary. No imported source or runtime dependencies.
- Accept an explicit normalized versioned JSON contract. Raw auditpol backup/get CSV mixes system/per-user/options and function-dependent numeric encodings; a future adapter needs separately verified formats and locale fixtures.
- Model one primary-source-confirmed GUID/profile only. Display labels are untrusted and cannot change interpretation.
- Distinguish supplied policy and context declarations from effective host coverage. Effective coverage is always unknown, even with every declaration true. Per-user scope cannot satisfy a system requirement.
- Fixed-clock replay and explicit future/stale status preserve time uncertainty. Invalid timezone minutes are rejected rather than normalized by Python.
- Use predecode byte/depth/numeric limits and strict schema types. Resource limits are contract choices for a small learning lab, not universal Windows export limits.
- Publish complete reports exclusively with a hard link; no weaker overwrite fallback. This requires a supporting trusted local filesystem and can be blocked in the app sandbox. Post-publication cleanup failure has distinct exit 3.
- Keep source hashes and full verification outputs local and ignored. No parent staging/commits, new repository, deployment, services, host configuration, external messaging or scheduler changes.
- Codex retained security-sensitive implementation/review after previously inadequate local drafting and failed selected free remote drafting. No retries, new provider requests or paid fallback. Native ECC installation is not claimed; installed entry-point skill used for self-review.
