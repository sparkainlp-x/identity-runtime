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
    assert s["former_weaknesses_accepted"] == 0
    md = adversarial.markdown(res)
    tampered = res["summary"]["ledger_verification"]["tamper_cases"]
    assert f"{tampered}/{tampered} reopened runtimes refused the next action" in md


def test_former_weaknesses_are_exercised_and_rejected():
    res = adversarial.run(seed=3, trials=2, timing_samples=0)
    assert set(res["former_weaknesses"]) == set(adversarial.FORMER_WEAKNESSES)
    for name, f in res["former_weaknesses"].items():
        assert f["attempts"] == 2 and f["accepted"] == 0, name
    outcomes = res["outcomes"]
    assert outcomes["proof_forgery_and_replay/proof_redeemed_twice"] == {"rejected:already_redeemed": 2}
    assert outcomes["proof_forgery_and_replay/proof_redeem_after_lease_revoked"] == {"rejected:lease_revoked": 2}
    assert outcomes["proof_forgery_and_replay/proof_redeem_after_version_superseded"] == {"rejected:version_not_active": 2}
    assert outcomes["proof_forgery_and_replay/lease_token_replay"] == {"refused:ApprovalError:nonce has already been used": 2}
    assert outcomes["proof_forgery_and_replay/lease_token_budget_changed"] == {"refused:ApprovalError:approval token does not verify": 2}
    assert outcomes["proof_forgery_and_replay/clear_halt_token_replay"] == {"refused:ApprovalError:approval token does not verify": 2}
    assert outcomes["proof_forgery_and_replay/module_token_replay_recommits_old_version"] == {"refused:ApprovalError:approval token does not verify": 2}


def test_check_flag_fails_when_a_former_weakness_is_accepted(monkeypatch, tmp_path):
    real = adversarial.run

    def regressed(*a, **kw):
        res = real(*a, **kw)
        res["former_weaknesses"]["lease_token_replay"]["accepted"] = 1
        res["summary"]["former_weaknesses_accepted"] = 1
        return res

    monkeypatch.setattr(adversarial, "run", regressed)
    assert adversarial.main(["--trials", "1", "--timing-samples", "0", "--out", str(tmp_path), "--check"]) == 1


def test_benchmark_reports_known_weaknesses_instead_of_hiding_them():
    res = adversarial.run(seed=7, trials=1, timing_samples=0)
    # The remaining documented limitation is listed with an explanation, not folded into the attack counts.
    assert set(res["weaknesses"]) == set(adversarial.WEAKNESS_NOTES) == {"operator_drops_tail_and_rewinds_head", "operator_rewrites_chain_and_head"}
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
    assert res["summary"]["former_weaknesses_accepted"] == 0
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
