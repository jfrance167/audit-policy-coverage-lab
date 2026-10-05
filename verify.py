"""Capture local verification, exact exit codes and source hashes. No downloads."""
import ast
import hashlib
import json
# Verification executes only the selected local Python and trusted project checks.
import subprocess  # nosec B404
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main():
    run = ROOT / "verification-runs" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    run.mkdir(parents=True, exist_ok=False)
    sources = sorted([*ROOT.glob("*.py"), *ROOT.glob("tests/*.py"), *ROOT.glob("fixtures/*.json")])
    hashes = {str(path.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources}
    syntax = []
    for source in sources:
        if source.suffix == ".py":
            ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
            syntax.append(str(source.relative_to(ROOT)))
    command = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]
    # Fixed unittest arguments, no input-derived commands and no shell.
    result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=60, shell=False)  # nosec B603
    (run / "tests.stdout.txt").write_bytes(result.stdout)
    (run / "tests.stderr.txt").write_bytes(result.stderr)
    demos = []
    for fixture in sorted(ROOT.glob("fixtures/*.json")):
        for format_name in ("json", "markdown"):
            command_demo = [sys.executable, "audit_coverage.py", str(fixture.relative_to(ROOT)), "--format", format_name, "--as-of", "2026-10-05T12:00:00Z"]
            # Fixture path is a data argument to our fixed script, never shell code.
            demo = subprocess.run(command_demo, cwd=ROOT, capture_output=True, timeout=10, shell=False)  # nosec B603
            (run / (fixture.stem + "." + format_name)).write_bytes(demo.stdout)
            (run / (fixture.stem + "." + format_name + ".stderr.txt")).write_bytes(demo.stderr)
            demos.append({"command": command_demo, "exit_code": demo.returncode})
    sast_command = [sys.executable, "-m", "bandit", "-r", "audit_coverage.py", "verify.py", "-f", "json"]
    # Fixed installed Bandit module and source paths; no downloads or shell.
    sast = subprocess.run(sast_command, cwd=ROOT, capture_output=True, timeout=60, shell=False)  # nosec B603
    (run / "bandit.json").write_bytes(sast.stdout)
    (run / "bandit.stderr.txt").write_bytes(sast.stderr)
    record = {"python": sys.version, "executable": sys.executable, "syntax": {"status": "PASS", "files": syntax},
              "tests": {"command": command, "exit_code": result.returncode}, "demos": demos, "source_sha256": hashes,
              "bandit": {"command": sast_command, "exit_code": sast.returncode},
              "limits": {"live_host_validation": "NOT APPLICABLE: offline scope", "CodeQL": "NOT RUN: no standalone owned repository or publication requested"}}
    (run / "report.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(str(run / "report.json"))
    print(result.stderr.decode(errors="replace"))
    return 0 if result.returncode == 0 and sast.returncode == 0 and all(d["exit_code"] == 0 for d in demos) else 1


if __name__ == "__main__":
    raise SystemExit(main())
