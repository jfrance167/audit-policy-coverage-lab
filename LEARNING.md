# Learning

A quiet event stream cannot distinguish disabled auditing, a missing matching SACL, inaccessible logs, retention loss, collector failure or an operation that never happened. This lab exposes those uncertainties rather than assigning a reassuring score.

Missing GUID is unknown; explicit false is a declared gap. A friendly translated name is not a security identifier. Per-user inclusion/exclusion settings cannot be interpreted as equivalent system settings.

Parser libraries accept more than a project's contract. Python accepts timezone minute 60 and normalizes it, so strict range validation must accompany ISO parsing. Booleans are Python integers, but must not be accepted as schema versions or numeric settings.

Exclusive output and complete output are separate properties. A flushed temporary file plus exclusive publication provides both; cleanup can still fail after successful publication, so the CLI must state whether a complete output exists.

The initial sandbox test failures were filesystem restrictions, not parser failures. The authorized offline suite passed without Windows elevation after leaving the app sandbox. This does not verify live Windows auditing.

Optional exercise: compare missing.json with disabled.json, then use a future `--as-of`/captured-time combination. Explain why neither the input hash nor a current freshness label authenticates the configuration.
