"""Scripted lifecycle demo used by `python -m identity_runtime demo` and the Pages site."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .runtime import IdentityRuntime

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PERSONALITY = REPO_ROOT / "personalities" / "tesla.json"
MALICIOUS = REPO_ROOT / "examples" / "malicious.json"


def run_demo(state_dir: str | None, personality: str | None = None) -> list[dict[str, Any]]:
    path = Path(personality) if personality else DEFAULT_PERSONALITY
    manifest = json.loads(path.read_text(encoding="utf-8"))
    avatar = manifest["avatar_id"]
    rt = IdentityRuntime(state_dir)
    steps: list[dict[str, Any]] = []

    def step(title: str, result: Any) -> Any:
        steps.append({"step": len(steps) + 1, "title": title, "result": result})
        return result

    up = step(f"Upload {path.name}: validate, compile policy, shadow simulation", rt.receive_personality(manifest))
    up.pop("simulation", None)
    mc = up["manifest_checksum"]
    for module in list(up["awaiting"]):
        step(f"alice approves {module}", rt.approve_module(avatar, mc, module, "alice"))
    for module in ("tool_policy", "safety_policy"):
        step(f"bob approves {module} (second, distinct quorum approver)", rt.approve_module(avatar, mc, module, "bob"))
    step("Human grants leases", [
        rt.grant_lease(avatar, "read_public_data", "alice", max_actions=5, ttl_seconds=3600),
        rt.grant_lease(avatar, "send_email", "alice", max_actions=1, ttl_seconds=600),
    ])
    step("Low-risk research action (autonomous)", rt.request_action(avatar, "read_public_data", "research", 0.2, "Look up the 1888 AC motor patents"))
    held = step("send_email is held for a human", rt.request_action(avatar, "send_email", "approved_outreach", 0.3, "Reply to a teacher's question"))
    if held.get("action_id"):
        step("bob approves the held email (lease consumed once)", rt.approve_action(held["action_id"], "bob"))
    step("Context outside policy is denied", rt.request_action(avatar, "read_public_data", "approved_outreach", 0.1))
    step("Never-grantable capability is denied", rt.request_action(avatar, "modify_safety_policy", "general", 0.0))
    step("Revoke send_email", rt.revoke_capability(avatar, "send_email", "Administrative revocation"))
    step("send_email after revocation", rt.request_action(avatar, "send_email", "approved_outreach", 0.3))
    if MALICIOUS.exists():
        bad = rt.receive_personality(json.loads(MALICIOUS.read_text(encoding="utf-8")))
        bad.pop("simulation", None)
        step("Malicious manifest is rejected", bad)
    step("Verify the hash-chained ledger", rt.verify())
    return steps
