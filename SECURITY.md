# Security model

This is a local educational tool, not a compliance or detection-assurance product. Only use synthetic or deliberately sanitized snapshots for systems you own or are authorized to analyze. A `sanitized` source marker is not an automatic privacy filter.

Threats addressed: malformed/data-hostile JSON, decoder resource exhaustion within published limits, spoofed labels, duplicate GUID ambiguity, misleading positive coverage conclusions, Markdown/control injection, input/output clobbering and partial report publication. Data never selects modules, commands or code to execute. The analyzer has no network or Windows configuration interface.

Boundaries: trust the Python runtime, project source, regular local input and destination directory. Existing destinations are refused. Output bytes are data, not safe to interpolate directly into arbitrary HTML or command interpreters. This is not a malware sandbox. Special devices/pipes, malicious concurrent parent-directory replacement and crash/power-loss durability are not addressed.

Supply-chain scope: runtime analyzer imports only standard-library modules. Installed Bandit is an optional verification tool and was not installed/updated here. Trusted verification tests launch fixed local Python scripts without a shell. No real audit exports, credentials or client/employer data belong in fixtures or portfolio history.

No hosted disclosure channel or contact automation is configured. Findings can be reviewed locally with Jake. Publication, merge or deployment requires his separate authorization.
