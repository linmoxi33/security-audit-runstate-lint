#!/usr/bin/env python3
"""Behaviour tests for security-audit-runstate-lint (stdlib only, offline)."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "bin", "security-audit-runstate-lint")

BASE_META = {
    "run_id": "run-1",
    "repo": "example/widget",
    "target": "/src/widget",
    "source_ref": "HEAD",
    "profile": "standard",
    "scope_paths": ["src/"],
    "budget": 10,
    "execution_policy": "sandboxed-source-and-local-only",
    "run_status": "complete",
}


def run_tool(*args):
    proc = subprocess.run([sys.executable, BIN] + list(args),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return proc.returncode, proc.stdout, proc.stderr


class RunStateLintTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="runstate-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def write(self, name, data):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            if isinstance(data, str):
                handle.write(data)
            else:
                json.dump(data, handle)
        return path

    def lint(self, meta=None, ledger=None, findings="[]", *extra):
        self.write("run-metadata.json", BASE_META if meta is None else meta)
        if ledger is not None:
            self.write("coverage-ledger.json", ledger)
        if findings is not None:
            self.write("findings.json", findings)
        code, out, err = run_tool(self.dir, "--json", *extra)
        return code, json.loads(out), err

    # --- behaviour: pass path -------------------------------------------------
    def test_complete_run_passes(self):
        code, payload, _ = self.lint(ledger=[{"coverage_id": "u1", "status": "covered"}])
        self.assertEqual(code, 0)
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["summary"], {"errors": 0, "warnings": 0})

    def test_example_run_complete_matches_expected_output(self):
        code, out, _ = run_tool(os.path.join(ROOT, "examples", "in", "run-complete"), "--json")
        self.assertEqual(code, 0)
        with open(os.path.join(ROOT, "examples", "out", "run-complete.json"), encoding="utf-8") as handle:
            expected = json.load(handle)
        actual = json.loads(out)
        expected.pop("run_dir")
        actual.pop("run_dir")
        self.assertEqual(expected, actual)

    def test_example_run_contradictory_matches_expected_output(self):
        code, out, _ = run_tool(os.path.join(ROOT, "examples", "in", "run-contradictory"), "--json")
        self.assertEqual(code, 1)
        with open(os.path.join(ROOT, "examples", "out", "run-contradictory.json"), encoding="utf-8") as handle:
            expected = json.load(handle)
        actual = json.loads(out)
        expected.pop("run_dir")
        actual.pop("run_dir")
        self.assertEqual(expected, actual)

    # --- behaviour: metadata contract ----------------------------------------
    def test_missing_required_field_is_reported(self):
        meta = dict(BASE_META)
        del meta["source_ref"]
        code, payload, _ = self.lint(meta=meta, ledger=[])
        self.assertEqual(code, 1)
        self.assertIn("RS004", [f["code"] for f in payload["findings"]])

    def test_wrong_execution_policy_fails(self):
        meta = dict(BASE_META, execution_policy="host-wide")
        code, payload, _ = self.lint(meta=meta, ledger=[])
        self.assertEqual(code, 1)
        self.assertIn("RS007", [f["code"] for f in payload["findings"]])

    def test_invalid_profile_and_budget(self):
        meta = dict(BASE_META, profile="fast", budget=-2)
        code, payload, _ = self.lint(meta=meta, ledger=[])
        codes = [f["code"] for f in payload["findings"]]
        self.assertEqual(code, 1)
        self.assertIn("RS006", codes)
        self.assertIn("RS009", codes)

    def test_scope_paths_must_be_string_array(self):
        code, payload, _ = self.lint(meta=dict(BASE_META, scope_paths="src/"), ledger=[])
        self.assertEqual(code, 1)
        self.assertIn("RS008", [f["code"] for f in payload["findings"]])

    def test_unknown_run_status_rejected(self):
        code, payload, _ = self.lint(meta=dict(BASE_META, run_status="Complete"), ledger=[])
        self.assertEqual(code, 1)
        self.assertIn("RS005", [f["code"] for f in payload["findings"]])

    # --- behaviour: incomplete_reason discipline -----------------------------
    def test_incomplete_without_reason_fails(self):
        code, payload, _ = self.lint(meta=dict(BASE_META, run_status="incomplete"), ledger=[])
        self.assertEqual(code, 1)
        self.assertIn("RS012", [f["code"] for f in payload["findings"]])

    def test_incomplete_with_undocumented_reason_fails(self):
        meta = dict(BASE_META, run_status="incomplete", incomplete_reason="validation budget exhausted ")
        code, payload, _ = self.lint(meta=meta, ledger=[])
        self.assertEqual(code, 1)
        self.assertIn("RS013", [f["code"] for f in payload["findings"]])

    def test_complete_with_incomplete_reason_fails(self):
        meta = dict(BASE_META, incomplete_reason="critic_budget_exhausted")
        code, payload, _ = self.lint(meta=meta, ledger=[])
        self.assertEqual(code, 1)
        self.assertIn("RS011", [f["code"] for f in payload["findings"]])

    def test_validation_budget_exhausted_requires_candidate_unit(self):
        meta = dict(BASE_META, run_status="incomplete", incomplete_reason="validation_budget_exhausted")
        code, payload, _ = self.lint(meta=meta, ledger=[{"coverage_id": "u1", "status": "covered"}])
        self.assertEqual(code, 1)
        self.assertIn("XC008", [f["code"] for f in payload["findings"]])

    def test_validation_budget_exhausted_with_candidate_passes(self):
        meta = dict(BASE_META, run_status="incomplete", incomplete_reason="validation_budget_exhausted")
        ledger = [{"coverage_id": "u1", "status": "candidate",
                   "result_fingerprints": ["widget:auth-bypass"]}]
        code, payload, _ = self.lint(meta=meta, ledger=ledger)
        self.assertEqual(code, 0)
        self.assertEqual(payload["status"], "pass")

    def test_no_audit_reason_with_units_fails(self):
        meta = dict(BASE_META, run_status="incomplete",
                    incomplete_reason="budget_cannot_fund_reconnaissance_and_reserves")
        code, payload, _ = self.lint(meta=meta, ledger=[{"coverage_id": "u1", "status": "covered"}])
        self.assertEqual(code, 1)
        self.assertIn("XC009", [f["code"] for f in payload["findings"]])

    # --- behaviour: cross-checks ---------------------------------------------
    def test_complete_with_candidate_unit_fails(self):
        ledger = [{"coverage_id": "u1", "status": "candidate",
                   "result_fingerprints": ["widget:auth-bypass"]}]
        code, payload, _ = self.lint(ledger=ledger)
        self.assertEqual(code, 1)
        self.assertIn("XC004", [f["code"] for f in payload["findings"]])

    def test_complete_with_planned_unit_fails(self):
        code, payload, _ = self.lint(ledger=[{"coverage_id": "u1", "status": "planned"}])
        self.assertEqual(code, 1)
        self.assertIn("XC005", [f["code"] for f in payload["findings"]])

    def test_complete_without_findings_json_fails(self):
        code, payload, _ = self.lint(ledger=[], findings=None)
        self.assertEqual(code, 1)
        self.assertIn("XC006", [f["code"] for f in payload["findings"]])

    def test_complete_without_ledger_warns_but_passes(self):
        code, payload, _ = self.lint(ledger=None)
        self.assertEqual(code, 0)
        self.assertEqual(payload["status"], "pass_with_warnings")
        self.assertIn("XC003", [f["code"] for f in payload["findings"]])

    def test_strict_mode_fails_on_warning(self):
        code, payload, _ = self.lint(None, None, "[]", "--strict")
        self.assertEqual(code, 1)
        self.assertEqual(payload["status"], "fail")

    # --- usage / input errors ------------------------------------------------
    def test_missing_run_directory_exits_2(self):
        code, out, _ = run_tool(os.path.join(self.dir, "nope"), "--json")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["status"], "error")

    def test_malformed_json_exits_1_with_rs002(self):
        self.write("run-metadata.json", "{not json")
        code, out, _ = run_tool(self.dir, "--json")
        self.assertEqual(code, 1)
        self.assertIn("RS002", [f["code"] for f in json.loads(out)["findings"]])

    def test_text_mode_reports_pass(self):
        self.write("run-metadata.json", BASE_META)
        self.write("coverage-ledger.json", [])
        self.write("findings.json", "[]")
        code, out, _ = run_tool(self.dir)
        self.assertEqual(code, 0)
        self.assertIn("PASS", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
