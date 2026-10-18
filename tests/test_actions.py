import pytest

from conftest import commit
from identity_runtime import ActionError, ApprovalError, LeaseError

A = "tesla-edu-guide"


@pytest.fixture
def rt(make_runtime, tesla):
    rt = make_runtime()
    commit(rt, tesla)
    return rt


def test_no_lease_no_action(rt):
    r = rt.request_action(A, "read_public_data", "research", 0.1)
    assert r == {"decision": "denied", "reason": "no_valid_lease", "ledger_seq": r["ledger_seq"]}


def test_low_risk_action_runs_autonomously_with_proof(rt):
    rt.grant_lease(A, "read_public_data", "alice", max_actions=2)
    r = rt.request_action(A, "read_public_data", "research", 0.2, "patent lookup")
    assert r["decision"] == "authorised_autonomously"
    assert r["proof"]["fabric"]["checkpoint"] is False
    assert rt.verify_proof(r["proof"])
    forged = dict(r["proof"], capability="send_email")
    assert not rt.verify_proof(forged)


def test_lease_budget_is_enforced(rt):
    rt.grant_lease(A, "read_public_data", "alice", max_actions=2)
    assert rt.request_action(A, "read_public_data", "research")["decision"] == "authorised_autonomously"
    assert rt.request_action(A, "read_public_data", "research")["decision"] == "authorised_autonomously"
    assert rt.request_action(A, "read_public_data", "research")["reason"] == "no_valid_lease"


def test_lease_expires(rt, clock):
    rt.grant_lease(A, "read_public_data", "alice", ttl_seconds=10)
    clock.advance(11)
    assert rt.request_action(A, "read_public_data", "research")["reason"] == "no_valid_lease"


def test_lease_limits_are_clamped(rt):
    lease = rt.grant_lease(A, "send_email", "alice", max_actions=999, ttl_seconds=10**9)
    assert lease["max_actions"] == 3  # persona said 3, registry allows 5
    assert lease["expires_ns"] - lease["issued_ns"] == 3600 * 10**9


def test_lease_ids_are_unique(rt):
    ids = {rt.grant_lease(A, "read_public_data", "alice")["lease_id"] for _ in range(20)}
    assert len(ids) == 20


def test_cannot_lease_unknown_or_forbidden(rt):
    with pytest.raises(LeaseError):
        rt.grant_lease(A, "post_public", "alice")  # not enabled by this persona
    with pytest.raises(LeaseError):
        rt.grant_lease(A, "modify_safety_policy", "alice")
    with pytest.raises(ApprovalError):
        rt.grant_lease(A, "read_public_data", A)


def test_send_email_is_held_then_approved_once(rt):
    rt.grant_lease(A, "send_email", "alice", max_actions=1)
    held = rt.request_action(A, "send_email", "approved_outreach", 0.0)
    assert held["decision"] == "held_for_human"
    assert "policy_requires_human" in held["reasons"]
    # the single unit is reserved, so a second request cannot slip in
    assert rt.request_action(A, "send_email", "approved_outreach")["reason"] == "no_valid_lease"
    with pytest.raises(ApprovalError):
        rt.approve_action(held["action_id"], A)  # avatar cannot approve its own action
    ok = rt.approve_action(held["action_id"], "bob")
    assert ok["decision"] == "authorised_by_human" and rt.verify_proof(ok["proof"])
    with pytest.raises(ActionError):
        rt.approve_action(held["action_id"], "carol")  # consumed once


def test_reject_action_releases_reservation(rt):
    rt.grant_lease(A, "send_email", "alice", max_actions=1)
    held = rt.request_action(A, "send_email", "approved_outreach")
    rt.reject_action(held["action_id"], "bob", "not now")
    again = rt.request_action(A, "send_email", "approved_outreach")
    assert again["decision"] == "held_for_human"


def test_declared_low_risk_cannot_undercut_capability_risk(rt):
    rt.grant_lease(A, "send_email", "alice")
    r = rt.request_action(A, "send_email", "approved_outreach", risk=-5)
    assert r["decision"] == "held_for_human"
    assert "oes61440_checkpoint" in r["reasons"]


def test_nan_risk_fails_closed(rt):
    rt.grant_lease(A, "read_public_data", "alice")
    r = rt.request_action(A, "read_public_data", "research", risk=float("nan"))
    assert r["decision"] == "held_for_human"
    assert "risk_at_or_above_autonomy_ceiling" in r["reasons"]


def test_declared_high_risk_on_low_risk_capability_is_held(rt):
    rt.grant_lease(A, "read_public_data", "alice")
    assert rt.request_action(A, "read_public_data", "research", risk=0.49)["decision"] == "authorised_autonomously"
    assert rt.request_action(A, "read_public_data", "research", risk=0.5)["decision"] == "held_for_human"


def test_high_risk_halts_and_requires_human_reset(rt):
    rt.grant_lease(A, "read_public_data", "alice")
    rt.grant_lease(A, "send_email", "alice", max_actions=3)
    for _ in range(2):  # two held requests reserve 2 of 3 units
        assert rt.request_action(A, "send_email", "approved_outreach")["decision"] == "held_for_human"
    r = rt.request_action(A, "send_email", "approved_outreach", risk=1.0)
    assert r["decision"] == "halted"
    assert all(l["state"] == "revoked" for l in rt.current_identity(A)["leases"])
    assert rt.request_action(A, "read_public_data", "research")["reason"] == "avatar_halted"
    with pytest.raises(LeaseError):
        rt.grant_lease(A, "read_public_data", "alice")
    rt.clear_halt(A, "bob", "reviewed")
    rt.grant_lease(A, "read_public_data", "alice")
    assert rt.request_action(A, "read_public_data", "research")["decision"] == "authorised_autonomously"


def test_context_and_policy_denials(rt):
    rt.grant_lease(A, "read_public_data", "alice")
    assert rt.request_action(A, "read_public_data", "approved_outreach")["reason"] == "context_not_allowed"
    assert rt.request_action(A, "post_public", "general")["reason"] == "capability_not_in_policy"
    assert rt.request_action(A, "modify_safety_policy")["reason"] == "never_grantable_capability"
    assert rt.request_action(A, "spend_money")["reason"] == "never_grantable_capability"


def test_revocation_removes_capability_and_cancels_held(rt):
    rt.grant_lease(A, "send_email", "alice")
    held = rt.request_action(A, "send_email", "approved_outreach")
    r = rt.revoke_capability(A, "send_email", "Administrative revocation")
    assert r["cancelled_actions"] == [held["action_id"]]
    assert rt.request_action(A, "send_email", "approved_outreach")["reason"] == "no_valid_lease"
    with pytest.raises(ActionError):
        rt.approve_action(held["action_id"], "bob")


def test_held_action_cancelled_if_lease_expires(rt, clock):
    rt.grant_lease(A, "send_email", "alice", ttl_seconds=5)
    held = rt.request_action(A, "send_email", "approved_outreach")
    clock.advance(6)
    with pytest.raises(ActionError, match="expired"):
        rt.approve_action(held["action_id"], "bob")
