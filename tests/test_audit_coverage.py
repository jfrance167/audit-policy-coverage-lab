"""Synthetic behavioral tests; no live Windows audit operations."""
import contextlib
import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import audit_coverage as lab

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 5, 12, tzinfo=timezone.utc)


def fixture():
    return {"schema_version": 1, "source_kind": "synthetic", "label": "owned lab example",
            "captured_at": "2026-10-05T11:00:00Z", "scope": "system",
            "subcategories": [{"guid": "{" + lab.FILE_SYSTEM_GUID.upper() + "}", "success": True, "failure": False}]}


def encode(data):
    return json.dumps(data).encode()


def report(data):
    raw = encode(data)
    return lab.evaluate(lab.parse_snapshot(raw), hashlib.sha256(raw).hexdigest(), now=NOW)


class ParserTests(unittest.TestCase):
    def reject(self, data):
        with self.assertRaises(lab.InputError):
            lab.parse_snapshot(encode(data))

    def test_normalized_guid(self):
        self.assertEqual(lab.parse_snapshot(encode(fixture()))["subcategories"][0]["guid"], lab.FILE_SYSTEM_GUID)

    def test_duplicate_fields_nested_and_root(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":{"b":1,"b":2}}'):
            with self.subTest(raw=raw), self.assertRaises(lab.InputError):
                lab.parse_snapshot(raw)

    def test_duplicate_canonical_guid(self):
        data = fixture()
        data["subcategories"].append({"guid": lab.FILE_SYSTEM_GUID, "success": False, "failure": False})
        self.reject(data)

    def test_guid_forms_rejected(self):
        for value in (" " + lab.FILE_SYSTEM_GUID, lab.FILE_SYSTEM_GUID + "}", "{bad}", 1, None):
            data = fixture()
            data["subcategories"][0]["guid"] = value
            with self.subTest(value=value):
                self.reject(data)

    def test_schema_integer_is_not_boolean_or_float(self):
        for value in (True, 1.0, "1", 2, None):
            data = fixture()
            data["schema_version"] = value
            with self.subTest(value=value):
                self.reject(data)

    def test_setting_true_types(self):
        for value in (0, 1, "true", [], {}):
            data = fixture()
            data["subcategories"][0]["success"] = value
            with self.subTest(value=value):
                self.reject(data)

    def test_declaration_types_and_unknown_keys(self):
        for declarations in ({"matching_sacl": 1}, {"extra": True}, [], None):
            data = fixture()
            data["declarations"] = declarations
            with self.subTest(value=declarations):
                self.reject(data)

    def test_unknown_fields_and_missing_fields(self):
        data = fixture()
        data["hostname"] = "private host"
        self.reject(data)
        data = fixture()
        del data["captured_at"]
        self.reject(data)

    def test_unknown_scope_source_and_empty_label(self):
        for key, value in (("scope", "effective"), ("source_kind", "live"), ("source_kind", []), ("label", "  "), ("label", None)):
            data = fixture()
            data[key] = value
            with self.subTest(key=key):
                self.reject(data)

    def test_bad_timestamp(self):
        for value in ("2026-10-05", "2026-10-05T12:00:00", "2026-02-30T12:00:00Z", "2026-10-05T12:00:00+99:00", "2026-10-05T12:00:00+00:60", "2026-10-05T12:00:00-01:99", 1):
            data = fixture()
            data["captured_at"] = value
            with self.subTest(value=value):
                self.reject(data)

    def test_string_bounds_and_surrogates(self):
        for value in ("x" * (lab.MAX_STRING + 1), "\ud800"):
            data = fixture()
            data["label"] = value
            self.reject(data)

    def test_count_bound(self):
        data = fixture()
        data["subcategories"] = [{}] * (lab.MAX_ENTRIES + 1)
        self.reject(data)

    def test_raw_byte_bound(self):
        with self.assertRaises(lab.InputError):
            lab.parse_snapshot(b" " * (lab.MAX_BYTES + 1))

    def test_depth_before_decode(self):
        with self.assertRaisesRegex(lab.InputError, "nesting"):
            lab.parse_snapshot(b"[" * (lab.MAX_DEPTH + 1) + b"0" + b"]" * (lab.MAX_DEPTH + 1))

    def test_number_limit_and_nonfinite(self):
        for value in ("1" * 33, "1e999", "NaN", "Infinity", "-Infinity"):
            with self.subTest(value=value), self.assertRaises(lab.InputError):
                lab.parse_snapshot(('{"schema_version":' + value + '}').encode())

    def test_malformed_encoding_and_json(self):
        for raw in (b"\xff", b"\xef\xbb\xbf{}", b"{", b"{} {}", b'{"a":"\x01"}', b"null"):
            with self.subTest(raw=raw), self.assertRaises(lab.InputError):
                lab.parse_snapshot(raw)

    def test_quoted_brackets_numbers_and_escapes(self):
        data = fixture()
        data["label"] = "[" * 20 + "9" * 40 + '\\"' + "]" * 20
        self.assertEqual(lab.parse_snapshot(encode(data))["label"], data["label"])

    def test_display_name_is_string(self):
        data = fixture()
        data["subcategories"][0]["display_name"] = 2
        self.reject(data)


class EvaluationTests(unittest.TestCase):
    def test_present_policy_keeps_context_unknown(self):
        result = report(fixture())
        self.assertEqual(result["policy"]["status"], "declared_policy_present")
        self.assertEqual({row["status"] for row in result["context"]}, {"unknown"})
        self.assertEqual(result["effective_coverage"], "unknown")

    def test_false_null_and_missing_differ(self):
        for value, status in ((False, "declared_policy_gap"), (None, "unknown")):
            data = fixture()
            data["subcategories"][0]["success"] = value
            self.assertEqual(report(data)["policy"]["status"], status)
        data["subcategories"] = []
        self.assertIn("missing", report(data)["policy"]["reason"])

    def test_per_user_cannot_satisfy_system_requirement(self):
        data = fixture()
        data["scope"] = "per_user"
        self.assertEqual(report(data)["policy"]["status"], "unknown")

    def test_all_declared_never_effective(self):
        data = fixture()
        data["declarations"] = dict.fromkeys(lab.CONTEXT_KEYS, True)
        result = report(data)
        self.assertEqual(result["effective_coverage"], "unknown")
        self.assertEqual({row["status"] for row in result["context"]}, {"declared_present"})

    def test_context_false_and_null(self):
        data = fixture()
        data["declarations"] = {"matching_sacl": False, "retention": None}
        statuses = {row["requirement"]: row["status"] for row in report(data)["context"]}
        self.assertEqual(statuses["matching_sacl"], "declared_gap")
        self.assertEqual(statuses["retention"], "unknown")

    def test_display_name_cannot_spoof_identity(self):
        data = fixture()
        baseline = report(data)["policy"]
        data["subcategories"][0]["display_name"] = "SYSTEM VERIFIED / 文件系统"
        self.assertEqual(report(data)["policy"], baseline)
        data["subcategories"][0]["guid"] = "00000000-0000-0000-0000-000000000000"
        result = report(data)
        self.assertEqual(result["policy"]["status"], "unknown")
        self.assertEqual(result["counts"]["unmodeled_subcategories"], 1)

    def test_current_stale_future_fixed_clock(self):
        for timestamp, status, age in (("2026-10-05T11:00:00Z", "current", 3600), ("2026-10-03T12:00:00Z", "stale", 172800), ("2026-10-05T12:00:01Z", "future", -1)):
            data = fixture()
            data["captured_at"] = timestamp
            result = report(data)
            self.assertEqual((result["freshness"]["status"], result["freshness"]["age_seconds"]), (status, age))
            self.assertEqual(result["effective_coverage"], "unknown")

    def test_timezone_equivalence_and_naive_clock_rejection(self):
        self.assertEqual(lab.parse_time("2026-10-05T08:00:00-04:00"), NOW)
        with self.assertRaises(lab.InputError):
            lab.evaluate(lab.parse_snapshot(encode(fixture())), "0" * 64, now=datetime(2026, 10, 5))

    def test_deterministic_no_input_mutation(self):
        snapshot = lab.parse_snapshot(encode(fixture()))
        before = copy.deepcopy(snapshot)
        first = lab.render(lab.evaluate(snapshot, "0" * 64, now=NOW), "json")
        second = lab.render(lab.evaluate(snapshot, "0" * 64, now=NOW), "json")
        self.assertEqual(first, second)
        self.assertEqual(snapshot, before)

    def test_markdown_injection_and_terminal_controls(self):
        data = fixture()
        data["label"] = '<script>alert(1)</script>\n| [x](https://bad.example)\x1b[31m\u202e'
        result = report(data)
        text = lab.render(result, "markdown").decode()
        self.assertNotIn("<script>", text)
        self.assertNotIn("[x](", text)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\u202e", text)
        self.assertNotIn("\n", result["source"]["label"])
        self.assertEqual(json.loads(lab.render(result, "json"))["effective_coverage"], "unknown")

    def test_render_output_bound_and_bad_format(self):
        result = report(fixture())
        with patch.object(lab, "MAX_OUTPUT", 10), self.assertRaises(lab.InputError):
            lab.render(result, "json")
        with self.assertRaises(lab.InputError):
            lab.render(result, "html")


class FileTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix=".test-audit-", dir=ROOT)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / "input.json"
        self.source.write_bytes(encode(fixture()))
        self.target = self.root / "report.json"

    def test_read_hash_binds_exact_bytes(self):
        snapshot, digest = lab.read_snapshot(self.source)
        self.assertEqual(digest, hashlib.sha256(self.source.read_bytes()).hexdigest())
        self.assertEqual(snapshot["scope"], "system")

    def test_read_oversized(self):
        self.source.write_bytes(b" " * (lab.MAX_BYTES + 1))
        with self.assertRaises(lab.InputError):
            lab.read_snapshot(self.source)

    def test_exclusive_complete_output(self):
        lab.write_report(self.target, b"complete", input_path=self.source)
        self.assertEqual(self.target.read_bytes(), b"complete")
        with self.assertRaises(lab.InputError):
            lab.write_report(self.target, b"replacement")
        self.assertEqual(self.target.read_bytes(), b"complete")
        self.assertEqual(list(self.root.glob("*.tmp")), [])

    def test_input_and_hardlink_alias_refused(self):
        original = self.source.read_bytes()
        with self.assertRaises(lab.InputError):
            lab.write_report(self.source, b"bad", input_path=self.source)
        os.link(self.source, self.target)
        with self.assertRaises(lab.InputError):
            lab.write_report(self.target, b"bad", input_path=self.source)
        self.assertEqual(self.source.read_bytes(), original)

    def test_publication_failure_cleans_partial(self):
        with patch.object(lab.os, "link", side_effect=OSError("synthetic failure")), self.assertRaises(OSError):
            lab.write_report(self.target, b"complete")
        self.assertFalse(self.target.exists())
        self.assertEqual(list(self.root.glob("*.tmp")), [])

    def test_flush_failure_cleans_partial(self):
        with patch.object(lab.os, "fsync", side_effect=OSError("synthetic failure")), self.assertRaises(OSError):
            lab.write_report(self.target, b"complete")
        self.assertFalse(self.target.exists())
        self.assertEqual(list(self.root.glob("*.tmp")), [])

    def test_cleanup_failure_after_publication_has_explicit_outcome(self):
        errors = io.StringIO()
        with patch.object(lab.Path, "unlink", side_effect=PermissionError("synthetic")), contextlib.redirect_stderr(errors):
            code = lab.main([str(self.source), "--output", str(self.target), "--as-of", "2026-10-05T12:00:00Z"])
        self.assertEqual(code, 3)
        self.assertIn("Complete report published", errors.getvalue())
        self.assertEqual(json.loads(self.target.read_bytes())["effective_coverage"], "unknown")
        self.assertEqual(len(list(self.root.glob("*.tmp"))), 1)

    def test_cleanup_failure_before_publication_is_distinct(self):
        with patch.object(lab.os, "link", side_effect=PermissionError("synthetic")), patch.object(lab.Path, "unlink", side_effect=PermissionError("synthetic")), self.assertRaises(lab.OutputCleanupError) as caught:
            lab.write_report(self.target, b"complete")
        self.assertFalse(caught.exception.published)
        self.assertFalse(self.target.exists())

    def test_competing_creation_is_preserved(self):
        real_link = os.link
        def competing(source, destination):
            Path(destination).write_bytes(b"other writer")
            return real_link(source, destination)
        with patch.object(lab.os, "link", side_effect=competing), self.assertRaises(FileExistsError):
            lab.write_report(self.target, b"ours")
        self.assertEqual(self.target.read_bytes(), b"other writer")

    def test_nonexistent_parent_and_output_size(self):
        with self.assertRaises(OSError):
            lab.write_report(self.root / "missing" / "report", b"report")
        with self.assertRaises(lab.InputError):
            lab.write_report(self.target, b"x" * (lab.MAX_OUTPUT + 1))
        self.assertFalse(self.target.exists())

    def test_cli_fixed_clock_and_exclusive_output(self):
        command = [sys.executable, str(ROOT / "audit_coverage.py"), str(self.source), "--as-of", "2026-10-05T12:00:00Z", "--output", str(self.target)]
        first = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(json.loads(self.target.read_bytes())["freshness"]["age_seconds"], 3600)
        original = self.target.read_bytes()
        second = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(second.returncode, 2)
        self.assertEqual(self.target.read_bytes(), original)

    def test_cli_invalid_input_no_output_or_private_path(self):
        self.source.write_bytes(b"not JSON")
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            code = lab.main([str(self.source), "--output", str(self.target)])
        self.assertEqual(code, 2)
        self.assertFalse(self.target.exists())
        self.assertNotIn(str(self.source), errors.getvalue())

    def test_cli_missing_input_redacts_path(self):
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            code = lab.main([str(self.root / "private-name.json")])
        self.assertEqual(code, 2)
        self.assertNotIn("private-name", errors.getvalue())

    def test_ascii_stdout_encoding_failure_is_redacted(self):
        data = fixture()
        data["label"] = "安全"
        self.source.write_bytes(encode(data))
        output = io.TextIOWrapper(io.BytesIO(), encoding="ascii")
        self.addCleanup(output.close)
        errors = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            self.assertEqual(lab.main([str(self.source), "--format", "markdown"]), 2)
        self.assertEqual(errors.getvalue(), "Rejected: output encoding failure\n")

    def test_short_stdout_and_flush_failure_not_success(self):
        class ShortWriter(io.StringIO):
            def write(self, text):
                return super().write(text[:-1])
        class BadFlush(io.StringIO):
            def flush(self):
                raise OSError("private detail")
        for output in (ShortWriter(), BadFlush()):
            errors = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                self.assertEqual(lab.main([str(self.source)]), 2)
            self.assertEqual(errors.getvalue(), "Rejected: OSError\n")


if __name__ == "__main__":
    unittest.main()
