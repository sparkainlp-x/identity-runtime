"""Single-use proofs, nonce-bound lease and rollback tokens, halt-bound and proposal-bound tokens."""
import copy
import json

import pytest
from conftest import ROOT, commit

from identity_runtime import ApprovalError, IdentityRuntime, LedgerIntegrityError
from identity_runtime.cli import main
from identity_runtime.signing import (
    lease_detail,
    module_detail,
    new_key,
    rollback_detail,
    sign,
)

A = "tesla-edu-guide"
NONCE = "n" * 16


def nonce(i):
    return f"nonce-{i:010d}-abcdef"


def v2(tesla):
    m = copy.deepcopy(tesla)
    m["display_name"] += " (v2)"
    return m


def halt(rt):
    rt.grant_lease(A, "send_email", "alice", max_actions=3)
    for _ in range(2):
        rt.request_action(A, "send_email", "approved_outreach")
    r = rt.request_action(A, "send_email", "approved_outreach", risk=1.0)
    assert r["decision"] == "halted"
    return r


@pytest.fixture
def rt(make_runtime, tesla):
    r = make_runtime()
    commit(r, tesla)
    return r


def authorised(rt, **lease):
    rt.grant_lease(A, "read_public_data", "alice", **({"max_actions": 5} | lease))
    r = rt.request_action(A, "read_public_data", "research", 0.1)
    assert r["decision"] == "authorised_autonomously"
    return r["proof"]


# ------------------------------------------------------------------ proofs
def test_proof_redeems_once(rt):
    proof = authorised(rt)
    assert rt.check_proof(proof) == {"valid": True, "reason": None}
    assert rt.check_proof(proof)["valid"]  # read-only: checking twice consumes nothing
    assert rt.verify_proof(proof)
    assert rt.redeem_proof(proof)["status"] == "redeemed"
    again = rt.redeem_proof(proof)
    assert again == {"status": "rejected", "reason": "already_redeemed", "ledger_seq": again["ledger_seq"]}
    assert not rt.verify_proof(proof)
    assert rt.proof_in_ledger(proof)  # the audit lookup still finds it
    events = [e["event"] for e in rt.ledger.entries]
    assert "proof_redeemed" in events and "proof_redemption_refused" in events


def test_redeemed_proofs_persist_across_restart(tmp_path, clock, tesla):
    rt = IdentityRuntime(str(tmp_path / "s"), clock=clock)
    commit(rt, tesla)
    proof = authorised(rt)
    assert rt.redeem_proof(proof)["status"] == "redeemed"
    fresh = IdentityRuntime(str(tmp_path / "s"), clock=clock)
    assert fresh.redeem_proof(proof)["reason"] == "already_redeemed"


def test_proof_rejected_after_lease_revoked(rt):
    proof = authorised(rt)
    rt.revoke_capability(A, "read_public_data", "stop")
    assert rt.check_proof(proof)["reason"] == "lease_revoked"
    assert rt.redeem_proof(proof)["status"] == "rejected"


def test_proof_rejected_after_lease_expired(rt, clock):
    proof = authorised(rt, ttl_seconds=60)
    clock.advance(61)
    assert rt.redeem_proof(proof)["reason"] == "lease_expired"


def test_proof_rejected_when_version_no_longer_active(rt, tesla):
    proof = authorised(rt)
    commit(rt, v2(tesla))
    assert rt.redeem_proof(proof)["reason"] == "version_not_active"
    rt.rollback(A, "carol")  # back to v1, but the lease was revoked by the commit
    assert rt.redeem_proof(proof)["reason"] == "lease_revoked"


def test_proof_rejected_while_halted(rt):
    proof = authorised(rt)
    halt(rt)
    assert rt.redeem_proof(proof)["reason"] == "avatar_halted"


def test_forged_and_held_proofs_do_not_redeem(rt):
    proof = authorised(rt)
    forged = dict(proof, capability="send_email")
    assert rt.redeem_proof(forged)["reason"] == "not_an_authorised_proof"
    rehashed = {k: v for k, v in forged.items() if k != "proof_hash"}
    from identity_runtime.util import checksum
    rehashed["proof_hash"] = checksum(rehashed)
    assert rt.redeem_proof(rehashed)["reason"] == "not_an_authorised_proof"
    assert rt.redeem_proof({"nonsense": True})["status"] == "rejected"


def test_human_approved_proof_redeems_once(rt):
    rt.grant_lease(A, "send_email", "alice", max_actions=1)
    held = rt.request_action(A, "send_email", "approved_outreach")
    ok = rt.approve_action(held["action_id"], "bob")
    assert rt.redeem_proof(ok["proof"])["status"] == "redeemed"
    assert rt.redeem_proof(ok["proof"])["reason"] == "already_redeemed"


# ------------------------------------------------------------ lease tokens
@pytest.fixture
def keys():
    return {"alice": new_key(), "bob": new_key(), "carol": new_key()}


@pytest.fixture
def srt(tmp_path, clock, tesla, keys):
    rt = IdentityRuntime(str(tmp_path / "signed"), clock=clock, approver_keys=keys)
    up = rt.receive_personality(tesla)
    mc, pid = up["manifest_checksum"], up["proposal_id"]
    for m in up["awaiting"]:
        rt.approve_module(A, mc, m, "alice", sign(keys["alice"], "module", A, mc, module_detail(m, pid), "alice"))
    for m in ("tool_policy", "safety_policy"):
        rt.approve_module(A, mc, m, "bob", sign(keys["bob"], "module", A, mc, module_detail(m, pid), "bob"))
    return rt


def lease_token(rt, keys, n, capability="read_public_data", who="alice", **kw):
    terms = rt.lease_terms(A, capability, kw.get("max_actions"), kw.get("ttl_seconds"))
    return sign(keys[who], "lease", A, terms["version"], lease_detail(terms, n), who)


def test_signed_lease_needs_a_nonce(srt, keys):
    tok = lease_token(srt, keys, "")
    with pytest.raises(ApprovalError, match="nonce is required"):
        srt.grant_lease(A, "read_public_data", "alice", signature=tok)


def test_signed_lease_token_is_single_use(srt, keys):
    tok = lease_token(srt, keys, nonce(1), max_actions=1)
    lease = srt.grant_lease(A, "read_public_data", "alice", max_actions=1, signature=tok, nonce=nonce(1))
    assert lease["max_actions"] == 1 and lease["nonce"] == nonce(1)
    with pytest.raises(ApprovalError, match="already been used"):
        srt.grant_lease(A, "read_public_data", "alice", max_actions=1, signature=tok, nonce=nonce(1))


def test_signed_lease_token_binds_the_terms(srt, keys):
    tok = lease_token(srt, keys, nonce(2), max_actions=1, ttl_seconds=60)
    for kw in ({"max_actions": 50, "ttl_seconds": 60}, {"max_actions": 1, "ttl_seconds": 3600}, {"max_actions": 1}):
        with pytest.raises(ApprovalError, match="does not verify"):
            srt.grant_lease(A, "read_public_data", "alice", signature=tok, nonce=nonce(2), **kw)
    with pytest.raises(ApprovalError, match="does not verify"):
        srt.grant_lease(A, "summarize_document", "alice", max_actions=1, ttl_seconds=60, signature=tok, nonce=nonce(2))
    # the failed attempts did not burn the nonce; the exact terms still work once
    assert srt.grant_lease(A, "read_public_data", "alice", max_actions=1, ttl_seconds=60, signature=tok, nonce=nonce(2))["max_actions"] == 1


def test_lease_terms_are_what_gets_granted(rt):
    terms = rt.lease_terms(A, "read_public_data", 10**6, 10**9)
    lease = rt.grant_lease(A, "read_public_data", "alice", 10**6, 10**9)
    assert terms["max_actions"] == lease["max_actions"] == 50
    assert terms["ttl_seconds"] * 10**9 == lease["expires_ns"] - lease["issued_ns"]
    assert terms["allowed_contexts"] == lease["allowed_contexts"] and terms["version"] == lease["version"]


def test_nonces_are_checked_without_a_keyring_too_and_persist(tmp_path, clock, tesla):
    rt = IdentityRuntime(str(tmp_path / "s"), clock=clock)
    commit(rt, tesla)
    rt.grant_lease(A, "read_public_data", "alice", nonce=NONCE)
    with pytest.raises(ApprovalError, match="already been used"):
        IdentityRuntime(str(tmp_path / "s"), clock=clock).grant_lease(A, "read_public_data", "alice", nonce=NONCE)
    with pytest.raises(ApprovalError, match="nonce must be"):
        rt.grant_lease(A, "read_public_data", "alice", nonce="short")


def test_signed_rollback_token_is_single_use(srt, keys, tesla):
    m2 = v2(tesla)
    up = srt.receive_personality(m2)
    mc, pid = up["manifest_checksum"], up["proposal_id"]
    for m in up["awaiting"]:
        srt.approve_module(A, mc, m, "alice", sign(keys["alice"], "module", A, mc, module_detail(m, pid), "alice"))
    for m in ("tool_policy", "safety_policy"):
        srt.approve_module(A, mc, m, "bob", sign(keys["bob"], "module", A, mc, module_detail(m, pid), "bob"))
    v1 = srt.current_identity(A)["history"][-1]
    back = sign(keys["carol"], "rollback", A, v1, rollback_detail(mc, nonce(3)), "carol")
    assert srt.rollback(A, "carol", v1, signature=back, nonce=nonce(3))["status"] == "rolled_back"
    fwd = sign(keys["carol"], "rollback", A, mc, rollback_detail(v1, nonce(4)), "carol")
    srt.rollback(A, "carol", mc, signature=fwd, nonce=nonce(4))
    with pytest.raises(ApprovalError, match="already been used"):
        srt.rollback(A, "carol", v1, signature=back, nonce=nonce(3))


# -------------------------------------------------------------- halt tokens
def test_clear_halt_token_binds_one_halt(srt, keys):
    def signed_halt():
        n = nonce(len(srt.store.state.get("used_nonces", {})) + 10)
        tok = lease_token(srt, keys, n, "send_email", max_actions=3)
        srt.grant_lease(A, "send_email", "alice", max_actions=3, signature=tok, nonce=n)
        for _ in range(2):
            srt.request_action(A, "send_email", "approved_outreach")
        r = srt.request_action(A, "send_email", "approved_outreach", risk=1.0)
        assert r["decision"] == "halted"
        return r["halt_id"]

    first = signed_halt()
    assert srt.current_identity(A)["halt_id"] == first
    tok1 = sign(keys["bob"], "clear_halt", A, first, "", "bob")
    root_tok = sign(keys["bob"], "clear_halt", A, srt.current_identity(A)["identity_root"], "", "bob")
    with pytest.raises(ApprovalError, match="does not verify"):
        srt.clear_halt(A, "bob", signature=root_tok)  # the old, root-bound format no longer verifies
    assert srt.clear_halt(A, "bob", signature=tok1)["status"] == "cleared"
    assert srt.clear_halt(A, "bob", signature=tok1)["status"] == "not_halted"
    second = signed_halt()
    assert second != first
    with pytest.raises(ApprovalError, match="does not verify"):
        srt.clear_halt(A, "bob", signature=tok1)
    assert srt.current_identity(A)["halted"]
    assert srt.clear_halt(A, "bob", signature=sign(keys["bob"], "clear_halt", A, second, "", "bob"))["status"] == "cleared"


def test_halt_ids_are_recorded(rt):
    r = halt(rt)
    assert rt.ledger.find("avatar_halted")[-1]["payload"]["halt_id"] == r["halt_id"]
    rt.clear_halt(A, "bob")
    assert rt.ledger.find("halt_cleared")[-1]["payload"]["halt_id"] == r["halt_id"]
    assert rt.current_identity(A)["halt_id"] is None


# ---------------------------------------------------------- module tokens
def test_reuploaded_superseded_manifest_needs_fresh_approval(tmp_path, clock, tesla, keys):
    rt = IdentityRuntime(str(tmp_path / "m"), clock=clock, approver_keys=keys)

    def signed_commit(manifest):
        up = rt.receive_personality(manifest)
        mc, pid = up["manifest_checksum"], up["proposal_id"]
        toks = {}
        for m in up["awaiting"]:
            toks[(m, "alice")] = sign(keys["alice"], "module", A, mc, module_detail(m, pid), "alice")
        for m in ("tool_policy", "safety_policy"):
            toks[(m, "bob")] = sign(keys["bob"], "module", A, mc, module_detail(m, pid), "bob")
        for (m, who), tok in toks.items():
            r = rt.approve_module(A, mc, m, who, tok)
        assert r["status"] == "committed"
        return mc, pid, toks

    v1, pid1, old = signed_commit(tesla)
    signed_commit(v2(tesla))
    up = rt.receive_personality(tesla)  # superseded v1 proposed again
    assert up["status"] == "pending_approval" and up["proposal_id"] != pid1
    for (m, who), tok in old.items():
        with pytest.raises(ApprovalError, match="does not verify"):
            rt.approve_module(A, v1, m, who, tok)
    assert rt.current_identity(A)["active"] != v1
    pid = up["proposal_id"]
    for m in up["awaiting"]:
        r = rt.approve_module(A, v1, m, "alice", sign(keys["alice"], "module", A, v1, module_detail(m, pid), "alice"))
    for m in ("tool_policy", "safety_policy"):
        r = rt.approve_module(A, v1, m, "bob", sign(keys["bob"], "module", A, v1, module_detail(m, pid), "bob"))
    assert r["status"] == "committed" and rt.current_identity(A)["active"] == v1


# ------------------------------------------------------------------ ledger
def test_tampered_ledger_keeps_the_specific_reason(tmp_path, clock, tesla):
    state = tmp_path / "t"
    rt = IdentityRuntime(str(state), clock=clock)
    commit(rt, tesla)
    path = state / "ledger.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[2])
    entry["payload"]["tampered"] = True
    lines[2] = json.dumps(entry)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    broken = IdentityRuntime(str(state), clock=clock)
    with pytest.raises(LedgerIntegrityError, match="line 3"):
        broken.request_action(A, "read_public_data", "research")


# --------------------------------------------------------------------- CLI
def test_cli_signed_lease_redeem_and_rollback(tmp_path, capsys):
    state, ring = tmp_path / "st", tmp_path / "ring.json"
    base = ["--state", str(state), "--keyring", str(ring)]
    tesla = str(ROOT / "personalities" / "tesla.json")
    assert main(["keygen", str(ring), "alice", "bob", "carol"]) == 0
    assert main([*base, "upload", tesla]) == 0
    assert main([*base, "approve", A, "all", "--as", "alice"]) == 0
    assert main([*base, "approve", A, "tool_policy", "safety_policy", "--as", "bob"]) == 0
    assert main([*base, "grant", A, "read_public_data", "--as", "alice", "--max-actions", "2"]) == 0
    capsys.readouterr()
    assert main([*base, "act", A, "read_public_data", "--context", "research", "--risk", "0.1"]) == 0
    action_id = json.loads(capsys.readouterr().out)["action_id"]
    assert main([*base, "check-proof", action_id]) == 0
    assert main([*base, "redeem", action_id]) == 0
    assert main([*base, "redeem", action_id]) == 5
    assert main([*base, "check-proof", action_id]) == 5
    m2 = tmp_path / "v2.json"
    m = json.loads((ROOT / "personalities" / "tesla.json").read_text(encoding="utf-8"))
    m["display_name"] += " (v2)"
    m2.write_text(json.dumps(m), encoding="utf-8")
    assert main([*base, "upload", str(m2)]) == 0
    assert main([*base, "approve", A, "all", "--as", "alice"]) == 0
    assert main([*base, "approve", A, "tool_policy", "safety_policy", "--as", "bob"]) == 0
    assert main([*base, "rollback", A, "--as", "carol"]) == 0
    assert main([*base, "verify"]) == 0
