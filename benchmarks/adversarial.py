"""Deterministic, seeded adversarial benchmark for identity-runtime (standard library only).

Every case drives the real runtime through its public API (``IdentityRuntime``
and the HMAC helpers in ``identity_runtime.signing``). Attacks that need to
edit files on disk (the ledger and ``state.json``) do so directly, the way an
attacker with file access would.

Each attempt is one of three kinds:

* ``attack``   - the runtime's own stated rules say it must refuse this. If it
                 is accepted, that is a *false approval*.
* ``control``  - a legitimate request that must be accepted, so the harness
                 cannot score well by refusing everything.
* ``weakness`` - an attack the current design does not claim to stop (today
                 only an operator rewriting both the ledger and state.json).
                 These are listed separately in ``weaknesses`` with an
                 explanation, so a reader sees exactly what gets through.

The replays the first version of this benchmark found getting through are now
``attack`` attempts; they are also tallied in ``former_weaknesses`` and
``--check`` fails if any of them is accepted again.

Outcomes depend only on the seed and the trial count. Timings depend on the
machine, which is not specified, and are not a performance claim.

    python benchmarks/adversarial.py                     # seed 61440, 20 trials, writes benchmarks/results.{json,md}
    python benchmarks/adversarial.py --trials 3 --out /tmp/bench --check
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import random
import re
import statistics
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from identity_runtime import (
    NEVER_GRANTABLE,
    ActionError,
    ApprovalError,
    IdentityRuntime,
    LeaseError,
    LedgerIntegrityError,
    __version__,
)
from identity_runtime.signing import lease_detail, module_detail, rollback_detail, sign
from identity_runtime.util import canonical_json, sha256_hex

SCHEMA = "identity-runtime/adversarial-benchmark-v1"
DEFAULT_SEED = 61440
DEFAULT_TRIALS = 20
DEFAULT_TIMING_SAMPLES = 50
TESLA = json.loads((ROOT / "personalities" / "tesla.json").read_text(encoding="utf-8"))
SPARKY = json.loads((ROOT / "personalities" / "sparky.json").read_text(encoding="utf-8"))
MALICIOUS = json.loads((ROOT / "examples" / "malicious.json").read_text(encoding="utf-8"))
A = TESLA["avatar_id"]
NOT_ENABLED = ("post_public", "write_sandbox_file", "schedule_reminder")  # in the registry, not enabled by tesla.json

CASES = {
    "unapproved_activation": "Activate or use a personality version that lacks its required human approvals.",
    "expired_lease": "Use a lease, or approve a held action, after the lease has expired.",
    "budget_exhaustion": "Act more times than the lease budget allows, or ask for a budget above the cap.",
    "scope_escalation": "Use or lease capabilities, contexts, risk levels or approvers outside the compiled policy.",
    "use_after_rollback_or_halt": "Use leases or held actions after a new commit, a rollback or an OES-61440 halt.",
    "ledger_tampering": "Edit, reorder, delete or truncate ledger lines, or rewrite ledger and state together.",
    "proof_forgery_and_replay": "Forge or replay action proofs and HMAC approval tokens.",
}

WEAKNESS_NOTES = {
    "operator_drops_tail_and_rewinds_head": "Someone who can write both ledger.jsonl and state.json can drop recent entries and move the recorded head back; verification passes. Documented: the ledger is tamper-evident, not tamper-proof.",
    "operator_rewrites_chain_and_head": "Someone who can write both files can edit an entry, recompute every later hash and update the recorded head; verification passes. Documented limitation; external anchoring is an open question.",
}

# Attacks that the first version of this benchmark showed getting through. They
# are now ordinary attacks (any acceptance is a false approval), and --check also
# fails if any of them is accepted again.
FORMER_WEAKNESSES = {
    "proof_redeemed_twice": "Proofs are single use: redeem_proof() records the action as redeemed (persisted in state.json) and refuses a second redemption.",
    "proof_check_after_redeem": "verify_proof()/check_proof() are current-only: a redeemed proof no longer verifies. proof_in_ledger() is the audit-only historical lookup.",
    "proof_redeem_after_lease_revoked": "A proof is refused once its lease is revoked.",
    "proof_redeem_after_version_superseded": "A proof is refused once its personality version is no longer active.",
    "lease_token_replay": "Signed lease grants need a nonce, which the runtime records; a replayed token and nonce are refused.",
    "lease_token_budget_changed": "The lease token binds the full effective terms (version, capability, contexts, human-review flag, max_actions, TTL); a different budget does not verify.",
    "lease_token_ttl_changed": "A different TTL does not verify either.",
    "clear_halt_token_replay": "A clear_halt token binds the specific halt id, so it cannot clear a later halt.",
    "module_token_replay_recommits_old_version": "Module tokens bind the upload's proposal id; re-uploading a superseded manifest creates a new proposal that needs fresh approvals.",
}


class FakeClock:
    def __init__(self, start: int = 1_800_000_000_000_000_000):
        self.now = start

    def __call__(self) -> int:
        self.now += 1_000
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += int(seconds * 1_000_000_000)


class Recorder:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def add(self, case: str, name: str, kind: str, fn: Callable[[], tuple[str, bool]]) -> bool:
        """Run fn, which returns (outcome, accepted). Exceptions count as refusals."""
        try:
            outcome, accepted = fn()
        except (ApprovalError, LeaseError, ActionError, LedgerIntegrityError) as exc:
            message = re.sub(r"[0-9a-f]{12,}", "<id>", str(exc).split(";")[0])
            outcome, accepted = f"refused:{type(exc).__name__}:{message}", False
        self.rows.append({"case": case, "attempt": name, "kind": kind, "outcome": outcome, "accepted": bool(accepted)})
        return bool(accepted)


# ----------------------------------------------------------------- helpers
def _keys(rng: random.Random) -> dict[str, bytes]:
    return {n: bytes(rng.getrandbits(8) for _ in range(32)) for n in ("alice", "bob", "carol")}


def _runtime(state_dir: str | None = None, keys: dict[str, bytes] | None = None, clock: FakeClock | None = None) -> tuple[IdentityRuntime, FakeClock]:
    clock = clock or FakeClock()
    return IdentityRuntime(state_dir, clock=clock, approver_keys=keys), clock


def _commit(rt: IdentityRuntime, manifest: dict[str, Any], keys: dict[str, bytes] | None = None) -> tuple[str, dict[tuple[str, str], str]]:
    avatar = manifest["avatar_id"]
    up = rt.receive_personality(manifest)
    assert up["status"] == "pending_approval", up
    mc = up["manifest_checksum"]
    pid = up["proposal_id"]
    tokens: dict[tuple[str, str], str] = {}
    result: dict[str, Any] = {}
    plan = [(m, "alice") for m in up["awaiting"]] + [(m, "bob") for m, n in up["awaiting"].items() if n == 2]
    for module, who in plan:
        tok = sign(keys[who], "module", avatar, mc, module_detail(module, pid), who) if keys else None
        if tok:
            tokens[(module, who)] = tok
        result = rt.approve_module(avatar, mc, module, who, tok)
    assert result["status"] == "committed", result
    return mc, tokens


def _variant(manifest: dict[str, Any], tag: str) -> dict[str, Any]:
    m = copy.deepcopy(manifest)
    m["display_name"] = f"{m['display_name']} ({tag})"
    return m


def _decision(r: dict[str, Any]) -> str:
    return r["decision"] + (f":{r['reason']}" if "reason" in r else "")


def _authorised(r: dict[str, Any]) -> bool:
    return r["decision"].startswith("authorised")


def _granted(rt: IdentityRuntime, *args: Any, **kw: Any) -> tuple[str, bool]:
    lease = rt.grant_lease(*args, **kw)
    return f"lease_granted(max_actions={lease['max_actions']})", True


def _halt(rt: IdentityRuntime) -> dict[str, Any]:
    """Drive the avatar into an OES-61440 halt the way tests/test_actions.py does."""
    rt.grant_lease(A, "send_email", "alice", max_actions=3)
    for _ in range(2):
        rt.request_action(A, "send_email", "approved_outreach")
    return rt.request_action(A, "send_email", "approved_outreach", risk=1.0)


# ------------------------------------------------------------------- cases
def case_unapproved_activation(rec: Recorder, rng: random.Random) -> None:
    c = "unapproved_activation"
    rt, _ = _runtime()
    up = rt.receive_personality(_variant(TESLA, f"t{rng.random():.6f}"))
    mc = up["manifest_checksum"]
    awaiting = list(up["awaiting"])
    missing = rng.choice(awaiting)
    for module in awaiting:
        if module != missing:
            rt.approve_module(A, mc, module, "alice")
    for module in ("tool_policy", "safety_policy"):
        if module == missing:
            rt.approve_module(A, mc, module, "alice")  # one of the two required people
        else:
            rt.approve_module(A, mc, module, "bob")
    root = rt.current_identity(A)["identity_root"]
    rec.add(c, "request_action_before_commit", "attack", lambda: (_decision(r := rt.request_action(A, "read_public_data", "research", 0.1)), _authorised(r)))
    rec.add(c, "grant_lease_before_commit", "attack", lambda: _granted(rt, A, "read_public_data", "alice"))
    rec.add(c, "avatar_self_approves", "attack", lambda: ("approved", rt.approve_module(A, mc, missing, A) is not None))
    reserved = rng.choice(["runtime:auto", "system", "self", "runtime-x", "avatar:" + A, "SYSTEM"])
    rec.add(c, "reserved_id_approves", "attack", lambda: ("approved", rt.approve_module(A, mc, missing, reserved) is not None))
    rec.add(c, "identity_root_approves", "attack", lambda: ("approved", rt.approve_module(A, mc, missing, root) is not None))
    rt.receive_personality(SPARKY)  # registers a second avatar id
    rec.add(c, "other_avatar_approves", "attack", lambda: ("approved", rt.approve_module(A, mc, missing, SPARKY["avatar_id"]) is not None))
    if missing in ("tool_policy", "safety_policy"):
        dup = rng.choice(["alice", "ALICE", "Alice"])
        rec.add(c, "same_person_twice_for_quorum", "attack", lambda: ("approved", rt.approve_module(A, mc, missing, dup) is not None))
    rec.add(c, "version_active_without_all_approvals", "attack", lambda: (f"active={rt.current_identity(A)['active'] is not None}", rt.current_identity(A)["active"] is not None))
    # control: the missing approval from a legitimate person commits it
    who = "carol"
    rec.add(c, "legitimate_final_approval_commits", "control", lambda: ((r := rt.approve_module(A, mc, missing, who))["status"], r["status"] == "committed"))
    # a second version, partly approved, must not replace the active one
    v2 = _variant(TESLA, "v2")
    up2 = rt.receive_personality(v2)
    for module in list(up2["awaiting"])[: rng.randint(0, len(up2["awaiting"]) - 1)]:
        rt.approve_module(A, up2["manifest_checksum"], module, "alice")
    rec.add(c, "partial_v2_replaces_active", "attack", lambda: (f"active_is_v2={rt.current_identity(A)['active'] == up2['manifest_checksum']}", rt.current_identity(A)["active"] == up2["manifest_checksum"]))


def case_expired_lease(rec: Recorder, rng: random.Random) -> None:
    c = "expired_lease"
    rt, clock = _runtime()
    _commit(rt, TESLA)
    ttl = rng.randint(1, 600)
    rt.grant_lease(A, "read_public_data", "alice", max_actions=10, ttl_seconds=ttl)
    rt.grant_lease(A, "send_email", "alice", max_actions=2, ttl_seconds=ttl)
    rec.add(c, "use_before_expiry", "control", lambda: (_decision(r := rt.request_action(A, "read_public_data", "research", 0.1)), _authorised(r)))
    held = rt.request_action(A, "send_email", "approved_outreach", 0.3)
    clock.advance(ttl + rng.randint(0, 120))
    rec.add(c, "use_after_expiry", "attack", lambda: (_decision(r := rt.request_action(A, "read_public_data", "research", 0.1)), _authorised(r)))
    rec.add(c, "approve_held_action_after_expiry", "attack", lambda: ((r := rt.approve_action(held["action_id"], "bob"))["decision"], _authorised(r)))
    rec.add(c, "send_email_after_expiry", "attack", lambda: (_decision(r := rt.request_action(A, "send_email", "approved_outreach", 0.3)), _authorised(r) or r["decision"] == "held_for_human"))


def case_budget_exhaustion(rec: Recorder, rng: random.Random) -> None:
    c = "budget_exhaustion"
    rt, _ = _runtime()
    _commit(rt, TESLA)
    k = rng.randint(1, 5)
    extra = rng.randint(1, 5)
    rt.grant_lease(A, "read_public_data", "alice", max_actions=k)
    for i in range(k + extra):
        kind = "control" if i < k else "attack"
        rec.add(c, "within_budget" if i < k else "over_budget", kind, lambda: (_decision(r := rt.request_action(A, "read_public_data", "research", 0.1)), _authorised(r) or r["decision"] == "held_for_human"))
    # one-unit send_email lease: a held action reserves the unit (larger send_email
    # leases run into the OES-61440 halt at 50% utilisation; see "observations")
    rt.grant_lease(A, "send_email", "alice", max_actions=1)
    held = [rt.request_action(A, "send_email", "approved_outreach", 0.3)]
    rec.add(c, "hold_beyond_reserved_budget", "attack", lambda: (_decision(r := rt.request_action(A, "send_email", "approved_outreach", 0.3)), r["decision"] != "denied"))
    for h in held:
        rt.approve_action(h["action_id"], "bob")
    rec.add(c, "after_all_held_approved", "attack", lambda: (_decision(r := rt.request_action(A, "send_email", "approved_outreach", 0.3)), r["decision"] != "denied"))
    rec.add(c, "approve_same_held_action_twice", "attack", lambda: (rt.approve_action(held[0]["action_id"], "carol")["decision"], True))
    asked = rng.choice([10**3, 10**6, 10**9])
    cap = 50  # tesla.json clamps read_public_data to 50 (registry cap 200)
    rec.add(c, "lease_budget_above_cap", "attack", lambda: (f"max_actions={(l := rt.grant_lease(A, 'read_public_data', 'alice', max_actions=asked))['max_actions']}", l["max_actions"] > cap))
    rec.add(c, "lease_ttl_above_cap", "attack", lambda: (f"ttl_s={((l := rt.grant_lease(A, 'read_public_data', 'alice', ttl_seconds=asked))['expires_ns'] - l['issued_ns']) // 10**9}", (l["expires_ns"] - l["issued_ns"]) // 10**9 > 86400))


def case_scope_escalation(rec: Recorder, rng: random.Random) -> None:
    c = "scope_escalation"
    rt, _ = _runtime()
    _commit(rt, TESLA)
    _commit(rt, SPARKY)
    rt.grant_lease(A, "read_public_data", "alice", max_actions=20)
    rt.grant_lease(A, "send_email", "alice", max_actions=3)
    cap = rng.choice(NOT_ENABLED)
    never = rng.choice(sorted(NEVER_GRANTABLE))
    rec.add(c, "request_capability_not_enabled", "attack", lambda: (_decision(r := rt.request_action(A, cap, "general", 0.1)), _authorised(r)))
    rec.add(c, "lease_capability_not_enabled", "attack", lambda: _granted(rt, A, cap, "alice"))
    rec.add(c, "request_never_grantable", "attack", lambda: (_decision(r := rt.request_action(A, never, "general", 0.0)), _authorised(r)))
    rec.add(c, "lease_never_grantable", "attack", lambda: _granted(rt, A, never, "alice"))
    rec.add(c, "unknown_capability", "attack", lambda: (_decision(r := rt.request_action(A, f"cap_{rng.randint(0, 9999)}", "general", 0.0)), _authorised(r)))
    ctx = rng.choice(["approved_outreach", "general", "admin", ""])
    rec.add(c, "context_outside_policy", "attack", lambda: (_decision(r := rt.request_action(A, "read_public_data", ctx, 0.1)), _authorised(r)))
    rec.add(c, "send_email_declared_zero_risk", "attack", lambda: (_decision(r := rt.request_action(A, "send_email", "approved_outreach", 0.0)), _authorised(r)))
    bad_risk = rng.choice([float("nan"), float("inf"), "low", None])
    rec.add(c, "malformed_risk_value", "attack", lambda: (_decision(r := rt.request_action(A, "read_public_data", "research", bad_risk)), _authorised(r)))
    held = rt.request_action(A, "send_email", "approved_outreach", 0.3)
    rec.add(c, "avatar_approves_own_held_action", "attack", lambda: (rt.approve_action(held["action_id"], A)["decision"], True))
    rec.add(c, "other_avatar_approves_held_action", "attack", lambda: (rt.approve_action(held["action_id"], SPARKY["avatar_id"])["decision"], True))
    rec.add(c, "legitimate_human_approves_held_action", "control", lambda: ((r := rt.approve_action(held["action_id"], "bob"))["decision"], _authorised(r)))
    # manifests that try to widen their own scope
    m = copy.deepcopy(TESLA)
    m["avatar_id"] = "escalation-probe"
    caps = m["modules"]["tool_policy"]["capabilities"]
    pick = rng.choice(["never", "unknown", "malicious"])
    if pick == "never":
        caps[never] = {"enabled": True}
        probe = m
    elif pick == "unknown":
        caps["launch_rockets"] = {"enabled": True}
        probe = m
    else:
        probe = MALICIOUS
    rec.add(c, "manifest_enables_forbidden_capability", "attack", lambda: ((r := rt.receive_personality(probe))["status"], r["status"] != "rejected"))
    m2 = copy.deepcopy(TESLA)
    m2["avatar_id"] = "clamp-probe"
    m2["modules"]["tool_policy"]["capabilities"]["send_email"]["requires_human_approval"] = False
    m2["modules"]["tool_policy"]["capabilities"]["read_public_data"]["max_actions"] = rng.choice([500, 10**6])
    compiled = rt.validate(m2)["compiled"]["capabilities"]
    rec.add(c, "manifest_drops_mandatory_human_approval", "attack", lambda: (f"requires_human={compiled['send_email']['requires_human_approval']}", not compiled["send_email"]["requires_human_approval"]))
    rec.add(c, "manifest_raises_limit_above_registry", "attack", lambda: (f"max_actions={compiled['read_public_data']['max_actions']}", compiled["read_public_data"]["max_actions"] > 200))


def case_use_after_rollback_or_halt(rec: Recorder, rng: random.Random, stats: dict[str, int]) -> None:
    c = "use_after_rollback_or_halt"
    rt, _ = _runtime()
    v1, _ = _commit(rt, TESLA)
    n_read = rng.randint(1, 3)
    for _ in range(n_read):
        rt.grant_lease(A, "read_public_data", "alice", max_actions=5)
    rt.grant_lease(A, "send_email", "alice", max_actions=2)
    held = rt.request_action(A, "send_email", "approved_outreach", 0.3)

    def check_revoked(event: str) -> None:
        ident = rt.current_identity(A)
        stats["leases_expected_revoked"] += len(ident["leases"])
        stats["leases_revoked"] += sum(1 for l in ident["leases"] if l["state"] == "revoked")
        stats["held_expected_cancelled"] += 1
        stats["held_cancelled"] += 0 if ident["held_actions"] else 1

    _commit(rt, _variant(TESLA, "v2"))
    check_revoked("commit")
    rec.add(c, "old_lease_after_new_commit", "attack", lambda: (_decision(r := rt.request_action(A, "read_public_data", "research", 0.1)), _authorised(r)))
    rec.add(c, "approve_held_after_new_commit", "attack", lambda: (rt.approve_action(held["action_id"], "bob")["decision"], True))
    rt.grant_lease(A, "read_public_data", "alice", max_actions=5)
    rt.grant_lease(A, "send_email", "alice", max_actions=2)
    held2 = rt.request_action(A, "send_email", "approved_outreach", 0.3)
    rec.add(c, "rollback_by_avatar", "attack", lambda: (rt.rollback(A, A)["status"], True))
    rt.rollback(A, "carol", reason="benchmark")
    rec.add(c, "rollback_restores_v1", "control", lambda: (f"active_is_v1={rt.current_identity(A)['active'] == v1}", rt.current_identity(A)["active"] == v1))
    check_revoked("rollback")
    rec.add(c, "lease_after_rollback", "attack", lambda: (_decision(r := rt.request_action(A, "read_public_data", "research", 0.1)), _authorised(r)))
    rec.add(c, "approve_held_after_rollback", "attack", lambda: (rt.approve_action(held2["action_id"], "bob")["decision"], True))
    rt.grant_lease(A, "read_public_data", "alice", max_actions=5)
    h = _halt(rt)
    rec.add(c, "halt_triggered", "control", lambda: (h["decision"], h["decision"] == "halted"))
    check_revoked("halt")
    rec.add(c, "act_while_halted", "attack", lambda: (_decision(r := rt.request_action(A, "read_public_data", "research", 0.1)), _authorised(r)))
    rec.add(c, "lease_while_halted", "attack", lambda: _granted(rt, A, "read_public_data", "alice"))
    rec.add(c, "avatar_clears_own_halt", "attack", lambda: ((r := rt.clear_halt(A, A))["status"], r["status"] == "cleared"))
    rt.clear_halt(A, "bob", "reviewed")
    rec.add(c, "old_lease_after_halt_cleared", "attack", lambda: (_decision(r := rt.request_action(A, "read_public_data", "research", 0.1)), _authorised(r)))
    rec.add(c, "fresh_lease_after_halt_cleared", "control", lambda: (_decision(r := (rt.grant_lease(A, "read_public_data", "alice"), rt.request_action(A, "read_public_data", "research", 0.1))[1]), _authorised(r)))


def _ledger_lines(d: str) -> list[str]:
    return Path(d, "ledger.jsonl").read_text(encoding="utf-8").splitlines()


def _write_lines(d: str, lines: list[str]) -> None:
    Path(d, "ledger.jsonl").write_text("".join(line + "\n" for line in lines), encoding="utf-8")


def _rehash_from(entries: list[dict[str, Any]], start: int) -> None:
    for i in range(start, len(entries)):
        e = entries[i]
        e["prev_hash"] = entries[i - 1]["hash"] if i else "0" * 64
        e["hash"] = sha256_hex(canonical_json({k: v for k, v in e.items() if k != "hash"}))


def _set_head(d: str, entries: list[dict[str, Any]]) -> None:
    p = Path(d, "state.json")
    state = json.loads(p.read_text(encoding="utf-8"))
    state["ledger_head"] = {"seq": entries[-1]["seq"], "hash": entries[-1]["hash"]}
    p.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def case_ledger_tampering(rec: Recorder, rng: random.Random, stats: dict[str, int]) -> None:
    c = "ledger_tampering"
    tampers = ["edit_payload", "edit_and_rehash_one_entry", "delete_middle_line", "swap_adjacent_lines", "truncate_last_line", "append_garbage_line", "drop_tail_lines"]
    weak = ["operator_drops_tail_and_rewinds_head", "operator_rewrites_chain_and_head"]
    for name in tampers + weak:
        with tempfile.TemporaryDirectory() as d:
            rt, clock = _runtime(d)
            _commit(rt, TESLA)
            rt.grant_lease(A, "read_public_data", "alice", max_actions=5)
            for _ in range(rng.randint(1, 3)):
                rt.request_action(A, "read_public_data", "research", 0.1)
            lines = _ledger_lines(d)
            entries = [json.loads(x) for x in lines]
            i = rng.randint(1, len(lines) - 3)
            if name == "edit_payload":
                entries[i]["payload"]["tampered"] = True
                lines[i] = canonical_json(entries[i])
            elif name == "edit_and_rehash_one_entry":
                entries[i]["payload"]["tampered"] = True
                entries[i]["hash"] = sha256_hex(canonical_json({k: v for k, v in entries[i].items() if k != "hash"}))
                lines[i] = canonical_json(entries[i])
            elif name == "delete_middle_line":
                del lines[i]
            elif name == "swap_adjacent_lines":
                lines[i], lines[i + 1] = lines[i + 1], lines[i]
            elif name == "append_garbage_line":
                lines.append('{"seq": 999, "event": "action_authorised"}')
            elif name == "drop_tail_lines":
                lines = lines[: -rng.randint(1, 2)]
            elif name == "operator_drops_tail_and_rewinds_head":
                entries = entries[: -rng.randint(1, 2)]
                lines = [canonical_json(e) for e in entries]
                _set_head(d, entries)
            elif name == "operator_rewrites_chain_and_head":
                entries[i]["payload"]["rewritten"] = True
                _rehash_from(entries, i)
                lines = [canonical_json(e) for e in entries]
                _set_head(d, entries)
            if name == "truncate_last_line":
                raw = Path(d, "ledger.jsonl").read_bytes()
                Path(d, "ledger.jsonl").write_bytes(raw[: -rng.randint(2, 40)])
            else:
                _write_lines(d, lines)
            reopened, _ = _runtime(d, clock=clock)
            verdict = reopened.verify()
            detected = not verdict["valid"]
            kind = "weakness" if name in weak else "attack"
            if kind == "attack":
                stats["tamper_cases"] += 1
                stats["tamper_detected"] += int(detected)
            else:
                stats["operator_rewrites"] += 1
                stats["operator_rewrites_detected"] += int(detected)
            rec.add(c, name, kind, lambda d=detected: ("detected" if d else "verified_as_valid", not d))
            if kind == "attack":
                rec.add(c, f"{name}:act_on_broken_ledger", "attack", lambda rr=reopened: (_decision(r := rr.request_action(A, "read_public_data", "research", 0.1)), _authorised(r)))


def _redeem(rt: IdentityRuntime, proof: dict[str, Any]) -> tuple[str, bool]:
    r = rt.redeem_proof(proof)
    return r["status"] + (f":{r['reason']}" if r.get("reason") else ""), r["status"] == "redeemed"


def case_proof_forgery_and_replay(rec: Recorder, rng: random.Random) -> None:
    c = "proof_forgery_and_replay"
    keys = _keys(rng)
    rt, clock = _runtime(keys=keys)
    v1, module_tokens = _commit(rt, TESLA, keys)

    def fresh() -> str:
        return f"{rng.getrandbits(128):032x}"

    def lease_token(capability: str, nonce: str, max_actions: int | None = None, ttl: int | None = None) -> str:
        terms = rt.lease_terms(A, capability, max_actions, ttl)
        return sign(keys["alice"], "lease", A, terms["version"], lease_detail(terms, nonce), "alice")

    def grant(capability: str, max_actions: int | None = None, ttl: int | None = None) -> tuple[str, str]:
        nonce = fresh()
        tok = lease_token(capability, nonce, max_actions, ttl)
        rt.grant_lease(A, capability, "alice", max_actions, ttl, signature=tok, nonce=nonce)
        return tok, nonce

    def act() -> dict[str, Any]:
        r = rt.request_action(A, "read_public_data", "research", 0.1)
        assert _authorised(r), r
        return r["proof"]

    def halt() -> str:
        grant("send_email", 3)
        for _ in range(2):
            rt.request_action(A, "send_email", "approved_outreach")
        r = rt.request_action(A, "send_email", "approved_outreach", risk=1.0)
        assert r["decision"] == "halted", r
        return r["halt_id"]

    budget = rng.randint(3, 5)
    lease_tok, lease_nonce = grant("read_public_data", budget, 600)
    proof = act()
    rec.add(c, "genuine_proof_checks_valid", "control", lambda: (str(v := rt.verify_proof(proof)), v))
    field, value = rng.choice([("capability", "send_email"), ("effective_risk", 0.0), ("context", "approved_outreach"), ("lease_id", "lease-forged"), ("avatar_id", "sparky-the-beaver")])
    mutated = dict(proof, **{field: value})
    rec.add(c, "mutated_proof_without_rehash", "attack", lambda: _redeem(rt, mutated))
    forged = {k: v for k, v in mutated.items() if k != "proof_hash"}
    forged["proof_hash"] = sha256_hex(canonical_json(forged))
    rec.add(c, "forged_proof_with_recomputed_hash", "attack", lambda: _redeem(rt, forged))
    other, _ = _runtime(keys=keys)
    rec.add(c, "proof_presented_to_other_runtime", "attack", lambda: (str(v := other.verify_proof(proof)), v))
    rec.add(c, "genuine_proof_redeems_once", "control", lambda: _redeem(rt, proof))
    rec.add(c, "proof_redeemed_twice", "attack", lambda: _redeem(rt, proof))
    rec.add(c, "proof_check_after_redeem", "attack", lambda: (str(v := rt.verify_proof(proof)), v))
    rec.add(c, "redeemed_proof_still_in_audit_ledger", "control", lambda: (str(v := rt.proof_in_ledger(proof)), v))
    # lease tokens: nonce and full terms
    rec.add(c, "lease_token_replay", "attack", lambda: _granted(rt, A, "read_public_data", "alice", budget, 600, signature=lease_tok, nonce=lease_nonce))
    n2 = fresh()
    one = lease_token("read_public_data", n2, 1, 60)
    rec.add(c, "lease_token_budget_changed", "attack", lambda: _granted(rt, A, "read_public_data", "alice", rng.choice([2, 50, 10**6]), 60, signature=one, nonce=n2))
    rec.add(c, "lease_token_ttl_changed", "attack", lambda: _granted(rt, A, "read_public_data", "alice", 1, rng.choice([61, 3600, 10**6]), signature=one, nonce=n2))
    rec.add(c, "lease_token_capability_changed", "attack", lambda: _granted(rt, A, "summarize_document", "alice", 1, 60, signature=one, nonce=n2))
    rec.add(c, "lease_signed_without_nonce", "attack", lambda: _granted(rt, A, "read_public_data", "alice", 1, 60, signature=one))
    rec.add(c, "lease_token_exact_terms_grant", "control", lambda: _granted(rt, A, "read_public_data", "alice", 1, 60, signature=one, nonce=n2))
    # proofs must be current: revoked lease, expired lease
    grant("read_public_data", 3, 600)
    p_revoked = act()
    rt.revoke_capability(A, "read_public_data", "benchmark")
    rec.add(c, "proof_redeem_after_lease_revoked", "attack", lambda: _redeem(rt, p_revoked))
    ttl = rng.randint(5, 120)
    grant("read_public_data", 3, ttl)
    p_expired = act()
    clock.advance(ttl + rng.randint(1, 60))
    rec.add(c, "proof_redeem_after_lease_expired", "attack", lambda: _redeem(rt, p_expired))
    # HMAC approval of held actions
    grant("send_email", 3)
    held = rt.request_action(A, "send_email", "approved_outreach", 0.3)
    held_proof = rt.ledger.find("action_held", action_id=held["action_id"])[0]["payload"]["proof"]  # held, not yet approved
    rec.add(c, "held_action_proof_presented", "attack", lambda: _redeem(rt, dict(held_proof)))
    rec.add(c, "random_token", "attack", lambda: (rt.approve_action(held["action_id"], "bob", f"{rng.getrandbits(256):064x}")["decision"], True))
    rec.add(c, "token_signed_by_other_approver", "attack", lambda: (rt.approve_action(held["action_id"], "bob", sign(keys["alice"], "action", A, held["action_id"], "send_email", "bob"))["decision"], True))
    held_b = rt.request_action(A, "send_email", "approved_outreach", 0.3)
    rec.add(c, "token_for_other_action", "attack", lambda: (rt.approve_action(held["action_id"], "bob", sign(keys["bob"], "action", A, held_b["action_id"], "send_email", "bob"))["decision"], True))
    rec.add(c, "token_for_other_capability", "attack", lambda: _granted(rt, A, "summarize_document", "alice", signature=lease_tok, nonce=fresh()))
    rec.add(c, "unsigned_approval_with_keyring", "attack", lambda: (rt.approve_action(held["action_id"], "bob")["decision"], True))
    good = sign(keys["bob"], "action", A, held["action_id"], "send_email", "bob")
    rec.add(c, "correct_token_approves", "control", lambda: ((r := rt.approve_action(held["action_id"], "bob", good))["decision"], _authorised(r)))
    rec.add(c, "replay_action_token", "attack", lambda: (rt.approve_action(held["action_id"], "bob", good)["decision"], True))
    # halts: proofs refused while halted; clear_halt tokens bind one halt
    grant("read_public_data", 3, 600)
    p_halted = act()
    first = halt()
    rec.add(c, "proof_redeem_while_halted", "attack", lambda: _redeem(rt, p_halted))
    root = rt.current_identity(A)["identity_root"]
    rec.add(c, "clear_halt_root_bound_token", "attack", lambda: ((r := rt.clear_halt(A, "bob", "old format", sign(keys["bob"], "clear_halt", A, root, "", "bob")))["status"], r["status"] == "cleared"))
    tok_first = sign(keys["bob"], "clear_halt", A, first, "", "bob")
    rec.add(c, "clear_halt_bound_token_clears", "control", lambda: ((r := rt.clear_halt(A, "bob", "first review", tok_first))["status"], r["status"] == "cleared"))
    second = halt()
    rec.add(c, "clear_halt_token_replay", "attack", lambda: ((r := rt.clear_halt(A, "bob", "replayed", tok_first))["status"], r["status"] == "cleared"))
    rec.add(c, "clear_halt_second_token_clears", "control", lambda: ((r := rt.clear_halt(A, "bob", "second review", sign(keys["bob"], "clear_halt", A, second, "", "bob")))["status"], r["status"] == "cleared"))
    # a proof issued under v1 is refused once v2 is active
    grant("read_public_data", 3, 600)
    p_v1 = act()
    v2, _ = _commit(rt, _variant(TESLA, "v2"), keys)
    rec.add(c, "proof_redeem_after_version_superseded", "attack", lambda: _redeem(rt, p_v1))
    # rollback tokens bind a nonce
    rn1, rn2 = fresh(), fresh()
    back = sign(keys["carol"], "rollback", A, v1, rollback_detail(v2, rn1), "carol")
    rec.add(c, "rollback_with_nonce", "control", lambda: ((r := rt.rollback(A, "carol", v1, "back", back, rn1))["status"], r["status"] == "rolled_back"))
    rt.rollback(A, "carol", v2, "forward", sign(keys["carol"], "rollback", A, v2, rollback_detail(v1, rn2), "carol"), rn2)
    rec.add(c, "rollback_token_replay", "attack", lambda: (rt.rollback(A, "carol", v1, "replayed", back, rn1)["status"], True))
    # re-uploading superseded v1: old module tokens must not re-commit it
    up = rt.receive_personality(TESLA)

    def replay_modules() -> tuple[str, bool]:
        for (module, who), tok in module_tokens.items():
            rt.approve_module(A, up["manifest_checksum"], module, who, tok)
        return "committed", rt.current_identity(A)["active"] == v1

    rec.add(c, "module_token_replay_recommits_old_version", "attack", replay_modules)

    def fresh_modules() -> tuple[str, bool]:
        r: dict[str, Any] = {}
        pid = up["proposal_id"]
        plan = [(m, "alice") for m in up["awaiting"]] + [(m, "bob") for m, n in up["awaiting"].items() if n == 2]
        for module, who in plan:
            r = rt.approve_module(A, up["manifest_checksum"], module, who, sign(keys[who], "module", A, up["manifest_checksum"], module_detail(module, pid), who))
        return r["status"], rt.current_identity(A)["active"] == v1

    rec.add(c, "fresh_module_approvals_recommit", "control", fresh_modules)


# ------------------------------------------------------------- observations
def observe_send_email_halt() -> dict[str, Any]:
    """How many ordinary send_email requests (declared risk 0) a lease of size m allows before a halt."""
    out = {}
    for m in range(1, 6):
        rt, _ = _runtime()
        _commit(rt, TESLA)
        rt.grant_lease(A, "send_email", "alice", max_actions=m)
        decisions = []
        for _ in range(m):
            r = rt.request_action(A, "send_email", "approved_outreach", 0.0)
            decisions.append(r["decision"])
            if r["decision"] == "halted":
                break
        out[str(m)] = decisions
    return {
        "send_email_lease_size_to_decisions": out,
        "explanation": "Lease utilisation ((used + reserved) / max_actions) is one of the four OES-61440 signals. With send_email's base risk of 0.7, every request made at utilisation 0.4 or more halted the avatar in these runs, even at declared risk 0, and requests at 1/3 or less were held normally. So no send_email lease of 1-5 units can carry more than two requests before a halt. This fails safe (nothing is authorised and every lease is revoked) but makes larger send_email leases unusable; it is an uncalibrated setting, not a bypass.",
    }


# ------------------------------------------------------------------ timing
def timing(samples: int) -> dict[str, Any]:
    def measure(state_dir: str | None) -> dict[str, list[float]]:
        rt, _ = _runtime(state_dir)
        _commit(rt, TESLA)
        out: dict[str, list[float]] = {"authorised": [], "denied": []}
        for _ in range(samples):
            rt.grant_lease(A, "respond_in_chat", "alice", max_actions=1)
            t0 = time.perf_counter()
            r = rt.request_action(A, "respond_in_chat", "education", 0.05)
            dt = time.perf_counter() - t0
            if _authorised(r):
                out["authorised"].append(dt)
            t0 = time.perf_counter()
            rt.request_action(A, "respond_in_chat", "admin", 0.05)
            out["denied"].append(time.perf_counter() - t0)
        return out

    def summary(xs: list[float]) -> dict[str, Any]:
        if not xs:
            return {"n": 0}
        return {"n": len(xs), "mean_ms": round(statistics.fmean(xs) * 1000, 3), "median_ms": round(statistics.median(xs) * 1000, 3)}

    mem = measure(None)
    with tempfile.TemporaryDirectory() as d:
        disk = measure(d)
    return {
        "machine": "unspecified",
        "note": "time.perf_counter() around one IdentityRuntime.request_action() call. 'authorised' runs every check plus the 61,440-channel OES-61440 evaluation and records a proof; 'denied' fails the context check before the tripwire runs. 'file_backed' adds ledger fsync and an atomic state.json write. Indicative only; varies by machine and Python version.",
        "in_memory": {k: summary(v) for k, v in mem.items()},
        "file_backed": {k: summary(v) for k, v in disk.items()},
    }


# ------------------------------------------------------------------ driver
def run(seed: int = DEFAULT_SEED, trials: int = DEFAULT_TRIALS, timing_samples: int = DEFAULT_TIMING_SAMPLES) -> dict[str, Any]:
    rng = random.Random(seed)
    rec = Recorder()
    rev = {"leases_expected_revoked": 0, "leases_revoked": 0, "held_expected_cancelled": 0, "held_cancelled": 0}
    led = {"tamper_cases": 0, "tamper_detected": 0, "operator_rewrites": 0, "operator_rewrites_detected": 0}
    for _ in range(trials):
        case_unapproved_activation(rec, rng)
        case_expired_lease(rec, rng)
        case_budget_exhaustion(rec, rng)
        case_scope_escalation(rec, rng)
        case_use_after_rollback_or_halt(rec, rng, rev)
        case_ledger_tampering(rec, rng, led)
        case_proof_forgery_and_replay(rec, rng)

    cases = {}
    for name, desc in CASES.items():
        rows = [r for r in rec.rows if r["case"] == name]
        attacks = [r for r in rows if r["kind"] == "attack"]
        controls = [r for r in rows if r["kind"] == "control"]
        weak = [r for r in rows if r["kind"] == "weakness"]
        rejected = sum(1 for r in attacks if not r["accepted"])
        cases[name] = {
            "description": desc,
            "attacks": len(attacks),
            "rejected": rejected,
            "rejection_rate": round(rejected / len(attacks), 4) if attacks else None,
            "false_approvals": len(attacks) - rejected,
            "controls": len(controls),
            "controls_passed": sum(1 for r in controls if r["accepted"]),
            "weakness_attempts": len(weak),
            "weakness_accepted": sum(1 for r in weak if r["accepted"]),
        }
    weaknesses = {}
    for r in rec.rows:
        if r["kind"] == "weakness":
            w = weaknesses.setdefault(r["attempt"], {"case": r["case"], "attempts": 0, "accepted": 0, "explanation": WEAKNESS_NOTES[r["attempt"]]})
            w["attempts"] += 1
            w["accepted"] += int(r["accepted"])
    former = {}
    for r in rec.rows:
        if r["attempt"] in FORMER_WEAKNESSES:
            f = former.setdefault(r["attempt"], {"case": r["case"], "attempts": 0, "accepted": 0, "fix": FORMER_WEAKNESSES[r["attempt"]]})
            f["attempts"] += 1
            f["accepted"] += int(r["accepted"])
    false_rows = [r for r in rec.rows if r["kind"] == "attack" and r["accepted"]]
    failed_controls = [r for r in rec.rows if r["kind"] == "control" and not r["accepted"]]
    outcomes: dict[str, dict[str, int]] = {}
    for r in rec.rows:
        key = f"{r['case']}/{r['attempt']}"
        outcomes.setdefault(key, {})
        outcomes[key][r["outcome"]] = outcomes[key].get(r["outcome"], 0) + 1
    total_attacks = sum(c["attacks"] for c in cases.values())
    return {
        "schema": SCHEMA,
        "identity_runtime_version": __version__,
        "seed": seed,
        "trials": trials,
        "summary": {
            "attacks": total_attacks,
            "rejected": total_attacks - len(false_rows),
            "rejection_rate": round((total_attacks - len(false_rows)) / total_attacks, 4) if total_attacks else None,
            "false_approvals": len(false_rows),
            "controls": sum(c["controls"] for c in cases.values()),
            "controls_failed": len(failed_controls),
            "rollback_revocation": {**rev, "lease_revocation_correctness": round(rev["leases_revoked"] / rev["leases_expected_revoked"], 4) if rev["leases_expected_revoked"] else None, "held_cancellation_correctness": round(rev["held_cancelled"] / rev["held_expected_cancelled"], 4) if rev["held_expected_cancelled"] else None},
            "ledger_verification": {**led, "detection_rate": round(led["tamper_detected"] / led["tamper_cases"], 4) if led["tamper_cases"] else None, "operator_rewrite_detection_rate": round(led["operator_rewrites_detected"] / led["operator_rewrites"], 4) if led["operator_rewrites"] else None},
            "weakness_acceptances": sum(w["accepted"] for w in weaknesses.values()),
            "former_weaknesses_accepted": sum(f["accepted"] for f in former.values()),
        },
        "cases": cases,
        "weaknesses": weaknesses,
        "former_weaknesses": former,
        "false_approval_details": false_rows,
        "failed_controls": failed_controls,
        "outcomes": outcomes,
        "observations": observe_send_email_halt(),
        "timing": timing(timing_samples) if timing_samples > 0 else None,
    }


def markdown(res: dict[str, Any]) -> str:
    s = res["summary"]
    out = [
        "# Adversarial benchmark results",
        "",
        f"Generated by `python benchmarks/adversarial.py --seed {res['seed']} --trials {res['trials']}` against identity-runtime {res['identity_runtime_version']}. Outcomes are deterministic for a given seed and trial count; timings are not.",
        "",
        "| Case | Attacks | Rejected | Rejection rate | False approvals | Controls passed | Weakness attempts accepted |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name, c in res["cases"].items():
        rate = "n/a" if c["rejection_rate"] is None else f"{c['rejection_rate']:.3f}"
        out.append(f"| {name} | {c['attacks']} | {c['rejected']} | {rate} | {c['false_approvals']} | {c['controls_passed']}/{c['controls']} | {c['weakness_accepted']}/{c['weakness_attempts']} |")
    out.append(f"| **total** | {s['attacks']} | {s['rejected']} | {s['rejection_rate']:.3f} | {s['false_approvals']} | {s['controls'] - s['controls_failed']}/{s['controls']} | {s['weakness_acceptances']} |")
    rr, lv = s["rollback_revocation"], s["ledger_verification"]
    broken = [r for r in res["outcomes"] if r.endswith(":act_on_broken_ledger")]
    refused = sum(n for r in broken for o, n in res["outcomes"][r].items() if o.startswith("refused:LedgerIntegrityError"))
    tried = sum(sum(res["outcomes"][r].values()) for r in broken)
    out += [
        "",
        f"- Revocation on commit, rollback and halt: {rr['leases_revoked']}/{rr['leases_expected_revoked']} leases revoked, {rr['held_cancelled']}/{rr['held_expected_cancelled']} held actions cancelled.",
        f"- Ledger tampering by someone who edits only `ledger.jsonl`: {lv['tamper_detected']}/{lv['tamper_cases']} detected; {refused}/{tried} reopened runtimes refused the next action as read-only.",
        f"- Ledger rewritten together with `state.json` (operator-level access): {lv['operator_rewrites_detected']}/{lv['operator_rewrites']} detected. This is the documented limit of a tamper-evident, not tamper-proof, ledger.",
        "",
        "## Former weaknesses, now rejected",
        "",
        "The first version of this benchmark found these replays getting through. They are now ordinary attacks (counted above), and `--check` fails if any of them is accepted again.",
        "",
        "| Attempt | Accepted | Fix |",
        "|---|---:|---|",
    ]
    for name, f in res["former_weaknesses"].items():
        out.append(f"| {name} | {f['accepted']}/{f['attempts']} | {f['fix']} |")
    out += [
        "",
        "## Remaining documented limitation",
        "",
        "These still get through. They are counted separately rather than as false approvals because the runtime does not claim to stop them; see [THREAT-MODEL.md](../THREAT-MODEL.md).",
        "",
        "| Attempt | Accepted | Why |",
        "|---|---:|---|",
    ]
    for name, w in res["weaknesses"].items():
        out.append(f"| {name} | {w['accepted']}/{w['attempts']} | {w['explanation']} |")
    t = res.get("timing")
    if t:
        out += [
            "",
            "## Overhead per authorization decision (machine unspecified)",
            "",
            "| Store | Path | n | Mean (ms) | Median (ms) |",
            "|---|---|---:|---:|---:|",
        ]
        for store in ("in_memory", "file_backed"):
            for path, v in t[store].items():
                if v["n"]:
                    out.append(f"| {store} | {path} | {v['n']} | {v['mean_ms']} | {v['median_ms']} |")
        out += ["", t["note"]]
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--seed", type=int, default=DEFAULT_SEED)
    p.add_argument("--trials", type=int, default=DEFAULT_TRIALS)
    p.add_argument("--timing-samples", type=int, default=DEFAULT_TIMING_SAMPLES)
    p.add_argument("--out", default=str(Path(__file__).resolve().parent), help="directory for results.json and results.md")
    p.add_argument("--check", action="store_true", help="exit 1 if any false approval or failed control")
    args = p.parse_args(argv)
    res = run(args.seed, args.trials, args.timing_samples)
    os.makedirs(args.out, exist_ok=True)
    Path(args.out, "results.json").write_text(json.dumps(res, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    md = markdown(res)
    Path(args.out, "results.md").write_text(md, encoding="utf-8")
    print(md)
    s = res["summary"]
    missing = set(FORMER_WEAKNESSES) - set(res["former_weaknesses"])
    if args.check and (s["false_approvals"] or s["controls_failed"] or s["former_weaknesses_accepted"] or missing):
        print(f"check failed: false approvals {s['false_approvals']}, failed controls {s['controls_failed']}, former weaknesses accepted {s['former_weaknesses_accepted']}, former-weakness cases missing {sorted(missing)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
