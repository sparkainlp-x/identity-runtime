"""Record the lifecycle of the Tesla-inspired example as data for the animated page.

Every value in the returned dictionary comes from running the real runtime in a
temporary directory: checksums, approvals, lease budgets, OES-61440 counts,
ledger hashes and the rejection reasons. Identity roots, lease ids and hashes
change on every run because they include time and random nonces.
"""

from __future__ import annotations

import copy
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from . import __version__, fabric
from .demo import DEFAULT_PERSONALITY, MALICIOUS
from .runtime import IdentityRuntime


def _fabric_view(proof_fabric: dict[str, Any]) -> dict[str, Any]:
    s = proof_fabric["signals"]
    d = fabric.evaluate(s["risk"], s["capability_risk"], s["context_mismatch"], s["lease_utilisation"], detail=True)
    for key in ("tripped_channels", "tripped_membranes", "tripped_sectors", "checkpoint", "halt"):
        assert d[key] == proof_fabric[key], key  # same inputs, same deterministic result
    return {
        "signals": s,
        "tripped_channels": d["tripped_channels"],
        "tripped_membranes": d["tripped_membranes"],
        "tripped_supervisors": d["tripped_supervisors"],
        "tripped_sectors": d["tripped_sectors"],
        "checkpoint": d["checkpoint"],
        "halt": d["halt"],
        "membrane_counts": d["membrane_counts"],
        "supervisor_trips": [int(x) for x in d["supervisor_trips"]],
        "sector_trips": [int(x) for x in d["sector_trips"]],
    }


def record_story(personality: str | None = None) -> dict[str, Any]:
    manifest = json.loads(Path(personality or DEFAULT_PERSONALITY).read_text(encoding="utf-8"))
    avatar = manifest["avatar_id"]
    tmp = tempfile.mkdtemp(prefix="identity-runtime-story-")
    try:
        state = str(Path(tmp) / "state")
        rt = IdentityRuntime(state)
        marks: dict[str, int] = {}

        def mark(name: str) -> None:
            marks[name] = rt.ledger.head()["seq"]

        up = rt.receive_personality(manifest)
        mc = up["manifest_checksum"]
        received = rt.ledger.find("personality_received")[0]["payload"]
        mark("upload")
        approvals = []
        singles = [m for m, n in up["awaiting"].items() if n == 1]
        quorum = [m for m, n in up["awaiting"].items() if n == 2]
        for m in singles + quorum:
            r = rt.approve_module(avatar, mc, m, "alice")
            approvals.append({"module": m, "approver": "alice", "status": r["status"]})
        mark("first_approvals")
        commit = None
        for m in quorum:
            r = rt.approve_module(avatar, mc, m, "bob")
            approvals.append({"module": m, "approver": "bob", "status": r["status"]})
            commit = r.get("commit", commit)
        mark("commit")

        lease_read = rt.grant_lease(avatar, "read_public_data", "alice", max_actions=5, ttl_seconds=3600)
        lease_mail = rt.grant_lease(avatar, "send_email", "alice", max_actions=1, ttl_seconds=600)
        mark("leases")
        low = rt.request_action(avatar, "read_public_data", "research", 0.2, "Look up the 1888 AC motor patents")
        mark("low_risk")
        held = rt.request_action(avatar, "send_email", "approved_outreach", 0.3, "Reply to a teacher's question")
        held_proof = rt._find_action(held["action_id"])[2]["proof"]
        mark("held")
        approved = rt.approve_action(held["action_id"], "bob")
        mark("approved")
        revoke = rt.revoke_capability(avatar, "send_email", "Administrative revocation")
        after_revoke = rt.request_action(avatar, "send_email", "approved_outreach", 0.3)
        mark("revoke")

        v2_manifest = copy.deepcopy(manifest)
        v2_manifest["manifest_version"] = "1.1.0"
        v2_manifest["modules"]["interaction"]["tone"] = "brisk and modern"
        up2 = rt.receive_personality(v2_manifest)
        for m in up2["awaiting"]:
            rt.approve_module(avatar, up2["manifest_checksum"], m, "alice")
        for m, n in up2["awaiting"].items():
            if n == 2:
                rt.approve_module(avatar, up2["manifest_checksum"], m, "bob")
        mark("v2_commit")
        rollback = rt.rollback(avatar, "carol", reason="tone change not wanted")
        mark("rollback")

        bad = rt.receive_personality(json.loads(MALICIOUS.read_text(encoding="utf-8")))
        mark("malicious")
        verify = rt.verify()

        # Tamper with a copy of the ledger and verify the copy.
        tampered_dir = str(Path(tmp) / "tampered")
        shutil.copytree(state, tampered_dir)
        lpath = Path(tampered_dir) / "ledger.jsonl"
        lines = lpath.read_text(encoding="utf-8").splitlines()
        target = next(i for i, line in enumerate(lines) if json.loads(line)["event"] == "module_approved")
        entry = json.loads(lines[target])
        original_approver = entry["payload"]["approver"]
        entry["payload"]["approver"] = "mallory"
        lines[target] = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        lpath.write_text("\n".join(lines) + "\n", encoding="utf-8")
        tampered_verify = IdentityRuntime(tampered_dir).verify()

        ledger = [
            {"seq": e["seq"], "event": e["event"], "hash": e["hash"], "prev_hash": e["prev_hash"]}
            for e in rt.ledger.entries
        ]
        ident = manifest["modules"]["identity"]
        return {
            "version": __version__,
            "avatar_id": avatar,
            "display_name": manifest["display_name"],
            "disclaimer": ident["disclaimer"],
            "identity_root": up["identity_root"],
            "manifest_checksum": mc,
            "policy_hash": up["policy_hash"],
            "policy_notes": up["policy_notes"],
            "module_checksums": received["module_checksums"],
            "auto_approved": received["auto_approved"],
            "required": {m: n for m, n in up["awaiting"].items()},
            "simulation": up["simulation"],
            "approvals": approvals,
            "commit": commit,
            "leases": [
                {k: lease[k] for k in ("lease_id", "capability", "max_actions", "requires_human_approval", "allowed_contexts", "granted_by", "issued_ns", "expires_ns")}
                for lease in (lease_read, lease_mail)
            ],
            "low_risk": {"decision": low["decision"], "proof_hash": low["proof"]["proof_hash"], "description": low["proof"]["description"],
                         "effective_risk": low["proof"]["effective_risk"], "fabric": _fabric_view(low["proof"]["fabric"])},
            "held": {"decision": held["decision"], "reasons": held["reasons"], "action_id": held["action_id"], "description": held_proof["description"],
                     "effective_risk": held_proof["effective_risk"], "fabric": _fabric_view(held_proof["fabric"])},
            "approved": {"decision": approved["decision"], "approved_by": approved["proof"]["approved_by"], "proof_hash": approved["proof"]["proof_hash"]},
            "revoke": {"revoked_leases": revoke["revoked_leases"], "after": after_revoke},
            "v2": {"manifest_checksum": up2["manifest_checksum"], "change": "interaction.tone -> 'brisk and modern'"},
            "rollback": rollback,
            "malicious": {"status": bad["status"], "stage": bad["stage"], "errors": bad["errors"]},
            "verify": verify,
            "tampered": {"line": target + 1, "field": "payload.approver", "from": original_approver, "to": "mallory", "verify": tampered_verify},
            "ledger": ledger,
            "marks": marks,
            "fabric_shape": {"channels": fabric.TOTAL_CHANNELS, "membranes": fabric.MEMBRANES, "supervisors": fabric.SUPERVISORS, "sectors": fabric.SECTORS,
                             "channels_per_membrane": fabric.CHANNELS_PER_MEMBRANE, "membrane_quorum": fabric.MEMBRANE_QUORUM,
                             "supervisor_quorum": fabric.SUPERVISOR_QUORUM, "sector_quorum": fabric.SECTOR_QUORUM},
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
