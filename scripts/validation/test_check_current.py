"""Independent fixtures for the current-version gate; no Cargo or product writes."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import contextlib
import io

SPEC = importlib.util.spec_from_file_location("check_current", Path(__file__).with_name("check-current.py"))
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def suite(target="sample", cases=("test good ... ok",), count=1, passed=1, failed=0, ignored=0, failures=()):
    listing = "\nfailures:\n    " + "\n    ".join(failures) + "\n" if failures else ""
    return ("     Running tests/%s.rs (target/debug/deps/%s-1234)\n\nrunning %d tests\n" % (target, target, count)
            + "\n".join(cases) + listing + "\n\ntest result: %s. %d passed; %d failed; %d ignored; 0 measured; 0 filtered out; finished in 0.01s\n" %
            ("FAILED" if failed else "ok", passed, failed, ignored))


def footer(*targets):
    return "".join("error: test failed, to rerun pass `-p demo --test %s`\n" % t for t in targets) + (
        "error: %d targets failed:\n" % len(targets)) + "".join("    `-p demo --test %s`\n" % t for t in targets)


class ParserTests(unittest.TestCase):
    def test_complete_case_and_empty_doc_target(self):
        text = suite() + "   Doc-tests demo\n\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
        result = gate.parse_log(text, 0)
        self.assertEqual(result["errors"], [])
        self.assertEqual([t["target"] for t in result["targets"]], ["sample", "doc::demo"])
        self.assertEqual(result["targets"][0]["cases"]["good"]["status"], "passed")

    def test_failure_list_and_cargo_footer_must_agree(self):
        text = suite(cases=("test bad ... FAILED",), passed=0, failed=1, failures=("bad",))
        self.assertFalse(gate.parse_log(text + footer("sample"), 101)["errors"])
        self.assertTrue(gate.parse_log(text + footer("other"), 101)["errors"])
        self.assertTrue(gate.parse_log(text + footer("sample").replace('--test sample','--test sample --skip good'), 101)["errors"])

    def test_missing_tail_and_compile_failure_cannot_pass(self):
        for text, code in [(suite().split("test result:")[0], 0), (suite()+"error[E0001]: compile failed\n", 101), (suite(), -15)]:
            self.assertTrue(gate.parse_log(text, code)["errors"])

    def test_missing_failed_case_name_cannot_pass(self):
        self.assertTrue(gate.parse_log(suite(cases=("test bad ... FAILED",), passed=0, failed=1)+footer("sample"), 101)["errors"])

    def test_application_error_debug_field_is_not_a_compiler_diagnostic(self):
        text=suite(cases=('test bad ... FAILED\n    error: ErrorDetail {\n        code: InvalidRequest,\n    }',),passed=0,failed=1,failures=('bad',))+footer('sample')
        self.assertFalse(gate.parse_log(text,101)['errors'])

    def test_wrong_outer_count_and_unknown_status_cannot_pass(self):
        self.assertTrue(gate.parse_log(suite(count=2), 0)["errors"])
        self.assertTrue(gate.parse_log(suite(cases=("test good ... mysterious",)), 0)["errors"])

    def test_nested_child_cases_are_not_counted_twice(self):
        nested = ("test child ... ok\nrunning 1 test\ntest child ... ok\n"
                  "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.01s\n"
                  "test parent ... ok")
        result = gate.parse_log(suite(cases=(nested,), count=2, passed=2), 0)
        self.assertFalse(result["errors"])
        self.assertEqual(len(result["targets"][0]["cases"]), 2)
        self.assertEqual(result["targets"][0]["summary"]["passed"], 2)

    def test_interleaved_nested_success_does_not_invent_runner_case(self):
        nested = ("test child ... \nrunning 1 test\nok\n"
                  "test child ... test other ... okok\n"
                  "test result: ok\nok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.01s\n")
        result = gate.parse_log(suite(cases=(nested,), count=2, passed=2), 0)
        self.assertFalse(result["errors"])
        self.assertEqual(result["targets"][0]["summary"]["passed"], 2)
        self.assertFalse(result["targets"][0]["cases"]["other"]["exact_pass"])

    def test_duplicate_outer_target_cannot_be_classified_ambiguously(self):
        self.assertTrue(gate.parse_log(suite()+suite(), 0)["errors"])

    def test_runner_single_executable_requires_supplied_target(self):
        raw = suite().split("\n", 1)[1]
        self.assertTrue(gate.parse_log(raw, 0)["errors"])
        result = gate.parse_log(raw, 0, runner_target="sample", require_footer=False)
        self.assertFalse(result["errors"])
        self.assertTrue(result["targets"][0]["cases"]["good"]["exact_pass"])

    def test_nocapture_receipt_before_exact_success(self):
        raw = suite(cases=('test good ... P06_R6_OBSERVED {"binding":"synthetic"}\nok',)).split("\n", 1)[1]
        result = gate.parse_log(raw, 0, runner_target="sample", require_footer=False)
        self.assertFalse(result["errors"])
        self.assertTrue(result["targets"][0]["cases"]["good"]["exact_pass"])


class GateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.classes = self.root / "classes"; self.classes.mkdir()
        self.evidence = self.root / "evidence"; self.evidence.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def declare(self, kind="historical", test="old"):
        value = [{"target":"sample", "test":test, "class":kind, "stage":"v0.1", "reason":"fixed old contract", "successor":"current normal runner"}]
        (self.classes / "sample-history.json").write_text(json.dumps(value))

    def run_gate(self, text, exit_code=101, change=None):
        log = self.root / "cargo.log"; log.write_text(text)
        manifest = {"schema_version":"gtkg.current-run/v1", "run_id":"run-1", "command":gate.CARGO_COMMAND,
            "exit_code":exit_code, "log_sha256":hashlib.sha256(log.read_bytes()).hexdigest(),
            "source_digest_before":"a"*64, "source_digest_after":"a"*64,
            "input_digest_before":"b"*64, "input_digest_after":"b"*64,
            "expected_targets":["sample"], "inventory_source_digest":"a"*64,
            "classification_sha256":gate.classification_digest(self.classes)}
        if change: manifest.update(change)
        path = self.root / "run.json"; path.write_text(json.dumps(manifest))
        return gate.evaluate(log, self.classes, self.evidence, path)

    def failed(self, test="old"):
        return suite(cases=("test %s ... FAILED" % test,), passed=0, failed=1, failures=(test,))+footer("sample")

    def test_only_exact_declared_history_is_excluded(self):
        self.declare()
        self.assertEqual(self.run_gate(self.failed())["status"], "passed")
        self.assertNotEqual(self.run_gate(self.failed("new_case"))["status"], "passed")

    def test_unknown_current_failure_and_stale_manifest_fail_closed(self):
        self.assertEqual(self.run_gate(self.failed())["status"], "failed")
        self.assertEqual(self.run_gate(suite(), 0, {"source_digest_after":"c"*64})["status"], "invalid")
        self.assertEqual(self.run_gate(suite(), 0, {"classification_sha256":"c"*64})["status"], "invalid")
        self.assertEqual(self.run_gate(suite(), 0, {"command":["cargo","test","--workspace","--locked"]})["status"], "invalid")

    def test_successful_but_partial_target_inventory_is_invalid(self):
        result=self.run_gate(suite(),0,{"expected_targets":["sample","missing","doc::demo"]})
        self.assertEqual(result['status'],'invalid')
        self.assertEqual(result['inventory']['missing_targets'],['doc::demo','missing'])
        self.assertEqual(self.run_gate(suite(),0,{"expected_targets":["other"]})['status'],'invalid')
        self.assertEqual(self.run_gate(suite(),0,{"expected_targets":["sample","sample"]})['status'],'invalid')
        self.assertEqual(self.run_gate(suite(),0,{"expected_targets":[]})['status'],'invalid')
        self.assertEqual(self.run_gate(suite(),0,{"inventory_source_digest":"c"*64})['status'],'invalid')

    def test_compile_error_cannot_hide_behind_successful_test_summary(self):
        for error in ('error[E0001]: failed compilation', '  error: could not compile demo', 'warning: build failed, waiting for other jobs to finish...'):
            self.assertEqual(self.run_gate(error+'\n'+suite(),0)['status'],'invalid')

    def test_duplicate_or_unknown_classification_rejected(self):
        self.declare()
        text=(self.classes/'sample-history.json').read_text()
        (self.classes/'duplicate-history.json').write_text(text)
        self.assertEqual(self.run_gate(self.failed())["status"], "invalid")

    def proof(self, **overrides):
        text=suite(cases=("test old ... ok",))
        log=self.evidence/'runner-test.log'; log.write_text(text)
        out=self.evidence/'runner.log'; out.write_text("real runner completed\n")
        obj={"schema_version":"gtkg.current-runner/v1", "run_id":"run-1", "source_digest":"a"*64,
             "input_digest":"b"*64, "command":["normal-runner"], "exit_code":0,
             "log":log.name,"log_sha256":hashlib.sha256(log.read_bytes()).hexdigest(),
             "stdout_log":out.name,"stdout_log_sha256":hashlib.sha256(out.read_bytes()).hexdigest(),
             "cases":[{"target":"sample","test":"old"}]}
        obj.update(overrides)
        (self.evidence/'normal.runner.json').write_text(json.dumps(obj))

    def test_runner_required_and_bound_to_this_run_source_and_input(self):
        self.declare("runner")
        self.assertEqual(self.run_gate(self.failed())["status"], "failed")
        self.proof()
        self.assertEqual(self.run_gate(self.failed())["status"], "passed")
        for change in ({"run_id":"yesterday"},{"source_digest":"c"*64},{"input_digest":"d"*64},{"exit_code":1},{"log_sha256":"e"*64}):
            self.proof(**change)
            self.assertNotEqual(self.run_gate(self.failed())["status"], "passed")

    def test_runner_case_claim_cannot_replace_log_or_escape_evidence_root(self):
        self.declare("runner")
        self.proof(cases=[{"target":"sample","test":"unseen"}])
        self.assertNotEqual(self.run_gate(self.failed())["status"], "passed")
        self.proof(log="../cargo.log")
        self.assertEqual(self.run_gate(self.failed())["status"], "invalid")
        (self.evidence/'normal.runner.json').write_text('[]')
        self.assertEqual(self.run_gate(self.failed())["status"], "invalid")

    def test_classification_digest_binds_names_and_original_bytes(self):
        self.declare()
        p=self.classes/'sample-history.json'
        expected=hashlib.sha256((p.name+'\0'+hashlib.sha256(p.read_bytes()).hexdigest()+'\n').encode()).hexdigest()
        self.assertEqual(gate.classification_digest(self.classes),expected)

    def test_unbound_diagnostic_is_not_a_successful_gate(self):
        log=self.root/'cargo.log';log.write_text(suite())
        stream=io.StringIO()
        with contextlib.redirect_stdout(stream):
            code=gate.main(['--inspect','--log',str(log),'--exit-code','0'])
        self.assertEqual(code,3)
        self.assertEqual(json.loads(stream.getvalue())['status'],'parsed_unbound')


if __name__ == "__main__":
    unittest.main()
