"""Offline declared audit prerequisites. No host configuration or collection APIs."""

import argparse
import hashlib
import json
import math
import os
import re
import sys
import tempfile
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

MAX_BYTES = 262144
MAX_DEPTH = 12
MAX_NUMBER = 32
MAX_ENTRIES = 128
MAX_STRING = 512
MAX_OUTPUT = 1048576
FILE_SYSTEM_GUID = "0cce921d-69ae-11d9-bed3-505054503030"
PROFILE = "file-system-success-4663/v1"
CONTEXT_KEYS = ("per_user_context", "gpo_context", "audit_options_context",
                "matching_sacl", "security_log_access", "retention", "collector_health")
TIME_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})\Z")
GUID_PATTERN = re.compile(r"(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\})\Z")


class InputError(ValueError):
    """Rejected data; messages do not echo untrusted content."""


class OutputCleanupError(OSError):
    """The output state is explicit even if temporary-file cleanup fails."""

    def __init__(self, published):
        super().__init__("temporary cleanup failed")
        self.published = published


def parse_time(value):
    if type(value) is not str or not TIME_PATTERN.fullmatch(value):
        raise InputError("timestamp must be ISO 8601 with seconds and an explicit timezone")
    if value[-1] != "Z" and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
        raise InputError("invalid timezone offset")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise InputError("invalid timestamp") from exc


def _scan(text):
    # Bound nesting and numeric tokens before the recursive JSON decoder runs.
    depth = 0
    inside = escaped = False
    number = 0
    for char in text:
        if inside:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                inside = False
            continue
        if char == '"':
            inside = True
        if char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise InputError("JSON nesting limit exceeded")
        elif char in "]}":
            depth -= 1
        if char in "0123456789.eE+-":
            number += 1
            if number > MAX_NUMBER:
                raise InputError("numeric token limit exceeded")
        else:
            number = 0


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("duplicate JSON field")
        result[key] = value
    return result


def _finite(value):
    number = float(value)
    if not math.isfinite(number):
        raise InputError("non-finite number")
    return number


def _constant(_value):
    raise InputError("non-finite number")


def _strings(value):
    if type(value) is str:
        if len(value) > MAX_STRING or any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise InputError("string limit exceeded or invalid Unicode scalar")
    elif type(value) is dict:
        for key, child in value.items():
            _strings(key)
            _strings(child)
    elif type(value) is list:
        for child in value:
            _strings(child)


def _fields(value, required, optional=()):
    if type(value) is not dict or not set(required) <= value.keys() or not value.keys() <= set(required) | set(optional):
        raise InputError("object fields do not match schema")


def _bool_or_null(value):
    if value is not None and type(value) is not bool:
        raise InputError("setting must be a boolean or null")


def parse_snapshot(raw):
    """Validate bounded UTF-8 bytes; GUID identity is independent of display names."""
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        raise InputError("input byte limit exceeded or input is not bytes")
    try:
        text = raw.decode("utf-8", errors="strict")
        _scan(text)
        data = json.loads(text, object_pairs_hook=_pairs, parse_float=_finite, parse_constant=_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise InputError("invalid UTF-8 JSON") from exc
    _strings(data)
    _fields(data, ("schema_version", "source_kind", "label", "captured_at", "scope", "subcategories"), ("declarations",))
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise InputError("unsupported schema version")
    if type(data["source_kind"]) is not str or data["source_kind"] not in ("synthetic", "sanitized"):
        raise InputError("unsupported source kind")
    if type(data["label"]) is not str or not data["label"].strip():
        raise InputError("label must be a nonempty string")
    parse_time(data["captured_at"])
    if type(data["scope"]) is not str or data["scope"] not in ("system", "per_user"):
        raise InputError("unsupported scope")
    rows = data["subcategories"]
    if type(rows) is not list or len(rows) > MAX_ENTRIES:
        raise InputError("subcategory count limit exceeded or invalid list")
    seen = set()
    for row in rows:
        _fields(row, ("guid", "success", "failure"), ("display_name",))
        if type(row["guid"]) is not str or not GUID_PATTERN.fullmatch(row["guid"]):
            raise InputError("invalid subcategory GUID")
        guid = row["guid"].strip("{}").lower()
        if guid in seen:
            raise InputError("duplicate canonical GUID")
        seen.add(guid)
        row["guid"] = guid
        _bool_or_null(row["success"])
        _bool_or_null(row["failure"])
        if "display_name" in row and type(row["display_name"]) is not str:
            raise InputError("display name must be a string")
    declarations = data.get("declarations", {})
    _fields(declarations, (), CONTEXT_KEYS)
    for value in declarations.values():
        _bool_or_null(value)
    return data


def read_snapshot(path):
    """Bound even growing files and bind provenance to the exact bytes consumed."""
    with Path(path).open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    return parse_snapshot(raw), hashlib.sha256(raw).hexdigest()


def safe_text(value):
    """Remove controls, bidi/invisible formatting before presentation."""
    return "".join(" " if unicodedata.category(c).startswith("C") else c for c in value)


def evaluate(snapshot, source_hash, *, now=None):
    """Pure analysis of validated declarations; never evaluates effective coverage."""
    clock = now if now is not None else datetime.now(timezone.utc)
    if not isinstance(clock, datetime) or clock.tzinfo is None or clock.utcoffset() is None:
        raise InputError("analysis clock must be timezone aware")
    age = (clock.astimezone(timezone.utc) - parse_time(snapshot["captured_at"])).total_seconds()
    freshness = "future" if age < 0 else "stale" if age > 86400 else "current"
    row = next((r for r in snapshot["subcategories"] if r["guid"] == FILE_SYSTEM_GUID), None)
    location = f"subcategories[{snapshot['subcategories'].index(row)}].success" if row else "subcategories"
    setting = row["success"] if row else None
    if snapshot["scope"] == "per_user":
        setting = None
        reason = "Per-user declarations cannot establish the system policy requirement."
    elif row is None:
        reason = "File System GUID is missing; absence is unknown, not disabled."
    elif setting is None:
        reason = "Success setting is explicitly unknown."
    elif setting:
        reason = "Successful File System auditing is declared enabled; matching SACL and collection remain separate."
    else:
        reason = "Successful File System auditing is declared disabled."
    status = "unknown" if setting is None else "declared_policy_present" if setting else "declared_policy_gap"
    contexts = []
    for key in CONTEXT_KEYS:
        declared = snapshot.get("declarations", {}).get(key)
        contexts.append({"requirement": key, "status": "unknown" if declared is None else "declared_present" if declared else "declared_gap",
                         "location": f"declarations.{key}", "reason": "Unverified supplied declaration; effective behavior is not measured." if declared is not None else "No declaration supplied; not inferred from system policy."})
    return {"report_version": 1, "profile": PROFILE,
            "source": {"kind": snapshot["source_kind"], "label": safe_text(snapshot["label"]), "sha256": source_hash,
                       "captured_at": snapshot["captured_at"], "scope": snapshot["scope"]},
            "analysis_at": clock.astimezone(timezone.utc).isoformat(),
            "freshness": {"status": freshness, "age_seconds": age, "stale_after_seconds": 86400},
            "counts": {"subcategories": len(snapshot["subcategories"]), "unmodeled_subcategories": len(snapshot["subcategories"]) - (1 if row else 0)},
            "policy": {"guid": FILE_SYSTEM_GUID, "event_id": 4663, "requirement": "Successful File System auditing", "status": status, "location": location, "reason": reason},
            "context": contexts, "effective_coverage": "unknown",
            "limitations": ["Declarations are not effective policy, compliance or evidence of event collection.",
                            "Source hash identifies input bytes; it does not authenticate their contents.",
                            "Per-user overrides, GPO and options require independently verified interpretation.",
                            "Future or stale snapshots cannot establish current configuration.",
                            "A matching SACL, account/access operation, readable retained events and a working collector are separate prerequisites."],
            "limits": {"input_bytes": MAX_BYTES, "depth": MAX_DEPTH, "numeric_token_chars": MAX_NUMBER, "subcategories": MAX_ENTRIES, "string_chars": MAX_STRING, "output_bytes": MAX_OUTPUT}}


def _markdown_text(value):
    # Encode all punctuation rather than allow user text to introduce Markdown/HTML.
    return "".join(c if c.isalnum() or c == " " else f"&#{ord(c)};" for c in safe_text(value))


def render(report, format_name):
    if format_name == "json":
        text = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"
    elif format_name == "markdown":
        source = report["source"]
        lines = ["# Declared audit prerequisites", "", "Effective coverage: **unknown**.", "",
                 f"Label: {_markdown_text(source['label'])}", f"Source kind: {source['kind']}",
                 f"Input SHA-256: `{source['sha256']}`", f"Profile: `{report['profile']}`",
                 f"Captured: {source['captured_at']}; analysis: {report['analysis_at']}",
                 f"Freshness: **{report['freshness']['status']}**; age seconds: {report['freshness']['age_seconds']}",
                 f"Scope: {source['scope']}; rows: {report['counts']['subcategories']}; unmodeled: {report['counts']['unmodeled_subcategories']}", "",
                 "| Prerequisite | Declared status | Location | Reason |", "|---|---|---|---|"]
        for row in [report["policy"], *report["context"]]:
            lines.append("| " + " | ".join(_markdown_text(str(row[k])) for k in ("requirement", "status", "location", "reason")) + " |")
        lines.extend(["", "Limitations:", "", *("- " + line for line in report["limitations"]), "", "Resource limits:", "", *(f"- {key}: {value}" for key, value in report["limits"].items())])
        text = "\n".join(lines) + "\n"
    else:
        raise InputError("unsupported report format")
    raw = text.encode("utf-8")
    if len(raw) > MAX_OUTPUT:
        raise InputError("output byte limit exceeded")
    return raw


def write_report(path, raw, *, input_path=None):
    """Publish one complete new file; existing destinations and aliases are refused.

    A sibling temporary file is flushed before an exclusive hard-link publication.
    A failure before publication cannot expose a partial report or replace a file.
    The destination filesystem must support hard links; there is no weaker fallback.
    """
    if type(raw) is not bytes or len(raw) > MAX_OUTPUT:
        raise InputError("output byte limit exceeded or output is not bytes")
    target = Path(path)
    if input_path is not None and target.resolve() == Path(input_path).resolve():
        raise InputError("output aliases input")
    if os.path.lexists(target):
        raise InputError("output already exists; exclusive creation required")
    temporary = None
    published = False
    try:
        with tempfile.NamedTemporaryFile(prefix=".audit-report-", suffix=".tmp", dir=target.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, target)
        published = True
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError as exc:
                raise OutputCleanupError(published) from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="explicit normalized JSON snapshot")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--output", type=Path, help="new output file; never overwritten")
    parser.add_argument("--as-of", help="fixed timezone-aware ISO timestamp for replay")
    args = parser.parse_args(argv)
    try:
        now = parse_time(args.as_of) if args.as_of else None
        snapshot, digest = read_snapshot(args.input)
        raw = render(evaluate(snapshot, digest, now=now), args.format)
        if args.output:
            write_report(args.output, raw, input_path=args.input)
        else:
            text = raw.decode("utf-8")
            if sys.stdout.write(text) != len(text):
                raise OSError("short stdout write")
            sys.stdout.flush()
        return 0
    except OutputCleanupError as exc:
        message = "Complete report published; temporary cleanup failed." if exc.published else "Report not published; temporary cleanup failed."
        print(message, file=sys.stderr)
        return 3 if exc.published else 2
    except UnicodeError:
        print("Rejected: output encoding failure", file=sys.stderr)
        return 2
    except (InputError, OSError) as exc:
        # Filesystem details can contain private paths; show only the error class.
        message = str(exc) if isinstance(exc, InputError) else type(exc).__name__
        print(f"Rejected: {message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
