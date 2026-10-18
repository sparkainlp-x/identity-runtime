import pytest

from conftest import commit
from identity_runtime import ApprovalError, IdentityRuntime


def test_tesla_uploads_passes_simulation_and_waits(make_runtime, tesla):
    rt = make_runtime()
    up = rt.receive_personality(tesla)
    assert up["status"] == "pending_approval"
    assert up["simulation"]["passed"] is True
    assert all(p["passed"] for p in up["simulation"]["probes"])
    assert up["awaiting"] == {"identity": 1, "reasoning": 1, "memory_policy": 1, "interaction": 1, "tool_policy": 2, "safety_policy": 2}
    ident = rt.current_identity("tesla-edu-guide")
    assert ident["active"] is None
    assert list(ident["pending"]) == [up["manifest_checksum"]]


def test_auto_modules_are_marked_approved(make_runtime, tesla):
    rt = make_runtime()
    up = rt.receive_personality(tesla)
    assert "voice" not in up["awaiting"] and "appearance" not in up["awaiting"]
    r = rt.approve_module("tesla-edu-guide", up["manifest_checksum"], "voice", "alice")
    assert r["status"] == "auto_approved"


def test_commit_needs_two_distinct_quorum_approvers(make_runtime, tesla):
    rt = make_runtime()
    up = rt.receive_personality(tesla)
    mc = up["manifest_checksum"]
    for m in up["awaiting"]:
        rt.approve_module("tesla-edu-guide", mc, m, "alice")
    with pytest.raises(ApprovalError, match="distinct"):
        rt.approve_module("tesla-edu-guide", mc, "safety_policy", "alice")
    with pytest.raises(ApprovalError, match="distinct"):
        rt.approve_module("tesla-edu-guide", mc, "safety_policy", "ALICE")
    assert rt.current_identity("tesla-edu-guide")["active"] is None
    rt.approve_module("tesla-edu-guide", mc, "safety_policy", "bob")
    r = rt.approve_module("tesla-edu-guide", mc, "tool_policy", "bob")
    assert r["status"] == "committed"
    assert rt.current_identity("tesla-edu-guide")["active"] == mc


@pytest.mark.parametrize("approver", ["tesla-edu-guide", "avatar:tesla", "runtime:auto", "self", "system", "", "bad id!"])
def test_avatar_and_reserved_ids_cannot_approve(make_runtime, tesla, approver):
    rt = make_runtime()
    up = rt.receive_personality(tesla)
    with pytest.raises(ApprovalError):
        rt.approve_module("tesla-edu-guide", up["manifest_checksum"], "identity", approver)


def test_identity_root_cannot_approve_and_another_avatar_cannot_approve(make_runtime, tesla, sparky):
    rt = make_runtime()
    up = rt.receive_personality(tesla)
    rt.receive_personality(sparky)
    with pytest.raises(ApprovalError):
        rt.approve_module("tesla-edu-guide", up["manifest_checksum"], "identity", up["identity_root"][:64])
    with pytest.raises(ApprovalError):
        rt.approve_module("tesla-edu-guide", up["manifest_checksum"], "identity", "sparky-the-beaver")


def test_approval_for_unknown_module_or_version(make_runtime, tesla):
    rt = make_runtime()
    up = rt.receive_personality(tesla)
    with pytest.raises(ApprovalError):
        rt.approve_module("tesla-edu-guide", up["manifest_checksum"], "not_a_module", "alice")
    with pytest.raises(ApprovalError):
        rt.approve_module("tesla-edu-guide", "0" * 64, "identity", "alice")


def test_identity_root_is_stable_across_versions(make_runtime, tesla):
    rt = make_runtime()
    commit(rt, tesla)
    root = rt.current_identity("tesla-edu-guide")["identity_root"]
    tesla["manifest_version"] = "1.0.1"
    up = rt.receive_personality(tesla)
    assert up["identity_root"] == root


def test_reupload_of_active_version(make_runtime, tesla):
    rt = make_runtime()
    commit(rt, tesla)
    assert rt.receive_personality(tesla)["status"] == "already_active"


def test_rollback_restores_previous_version_and_revokes_leases(make_runtime, tesla):
    rt = make_runtime()
    v1 = commit(rt, tesla)
    tesla["manifest_version"] = "1.1.0"
    tesla["modules"]["interaction"]["tone"] = "brisk"
    lease_v1 = rt.grant_lease("tesla-edu-guide", "read_public_data", "alice")
    v2 = commit(rt, tesla)
    ident = rt.current_identity("tesla-edu-guide")
    assert ident["active"] == v2 and ident["history"] == [v1]
    states = {l["lease_id"]: l["state"] for l in ident["leases"]}
    assert states[lease_v1["lease_id"]] == "revoked"  # commit revokes old leases

    lease_v2 = rt.grant_lease("tesla-edu-guide", "read_public_data", "alice")
    r = rt.rollback("tesla-edu-guide", "carol", reason="tone regression")
    assert r["active"] == v1 and lease_v2["lease_id"] in r["revoked_leases"]
    ident = rt.current_identity("tesla-edu-guide")
    assert ident["active"] == v1 and ident["history"] == [v2]
    # roll forward again by checksum
    assert rt.rollback("tesla-edu-guide", "carol", to_checksum=v2)["active"] == v2


def test_rollback_persists_across_restart(tmp_path, clock, tesla):
    state = str(tmp_path / "s")
    rt = IdentityRuntime(state, clock=clock)
    v1 = commit(rt, tesla)
    tesla["manifest_version"] = "2"
    commit(rt, tesla)
    rt.rollback("tesla-edu-guide", "carol")
    rt2 = IdentityRuntime(state, clock=clock)
    assert rt2.current_identity("tesla-edu-guide")["active"] == v1
    assert rt2.verify()["valid"]


def test_rollback_guards(make_runtime, tesla):
    rt = make_runtime()
    v1 = commit(rt, tesla)
    with pytest.raises(ApprovalError):
        rt.rollback("tesla-edu-guide", "carol")  # no history
    with pytest.raises(ApprovalError):
        rt.rollback("tesla-edu-guide", "carol", to_checksum=v1)  # already active
    with pytest.raises(ApprovalError):
        rt.rollback("tesla-edu-guide", "carol", to_checksum="f" * 64)  # never committed


def test_sparky_commits(make_runtime, sparky):
    rt = make_runtime()
    commit(rt, sparky)
    assert rt.current_identity("sparky-the-beaver")["character_type"] == "mascot"
