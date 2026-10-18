import ast
import json
import sys

from conftest import ROOT

sys.path.insert(0, str(ROOT / "benchmarks"))
import adversarial


def test_benchmark_has_no_false_approvals_and_all_controls_pass():
    res = adversarial.run(seed=7, trials=2, timing_samples=2)
    s = res["summary"]
    assert s["false_approvals"] == 0, res["false_approval_details"]
    assert s["controls_failed"] == 0, res["failed_controls"]
    assert s["attacks"] > 100 and s["rejection_rate"] == 1.0
    assert set(res["cases"]) == set(adversarial.CASES)
    for name, case in res["cases"].items():
        assert case["attacks"] > 0, name
    assert s["rollback_revocation"]["lease_revocation_correctness"] == 1.0
    assert s["rollback_revocation"]["held_cancellation_correctness"] == 1.0
    assert s["ledger_verification"]["detection_rate"] == 1.0
    assert res["timing"]["machine"] == "unspecified"


def test_benchmark_reports_known_weaknesses_instead_of_hiding_them():
    res = adversarial.run(seed=7, trials=1, timing_samples=0)
    # Every weakness attempt is listed with an explanation; none is folded into the attack counts.
    assert set(res["weaknesses"]) == set(adversarial.WEAKNESS_NOTES)
    assert res["summary"]["weakness_acceptances"] == sum(w["accepted"] for w in res["weaknesses"].values())
    assert res["summary"]["ledger_verification"]["operator_rewrites"] == 2
    md = adversarial.markdown(res)
    for name in adversarial.WEAKNESS_NOTES:
        assert name in md


def test_benchmark_outcomes_are_deterministic_for_a_seed():
    a = adversarial.run(seed=11, trials=1, timing_samples=0)
    b = adversarial.run(seed=11, trials=1, timing_samples=0)
    assert a == b


def test_committed_results_have_zero_false_approvals():
    res = json.loads((ROOT / "benchmarks" / "results.json").read_text(encoding="utf-8"))
    assert res["summary"]["false_approvals"] == 0
    assert res["summary"]["controls_failed"] == 0
    assert res["identity_runtime_version"] == adversarial.__version__


def test_benchmark_is_stdlib_only():
    stdlib = set(sys.stdlib_module_names) | {"__future__", "identity_runtime"}
    tree = ast.parse((ROOT / "benchmarks" / "adversarial.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            names = [node.module]
        else:
            continue
        for n in names:
            assert n.split(".")[0] in stdlib, n
