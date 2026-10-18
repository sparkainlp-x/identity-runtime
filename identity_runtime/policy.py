"""Runtime-side capability registry and the policy compiler.

The registry lives in the runtime, not in the persona. A personality manifest
can only switch on capabilities the registry knows about, and can only make
them stricter: it can lower limits, narrow contexts and add human approval,
but never raise a limit, drop a runtime-mandated approval or enable a
capability on the never-grantable list.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .util import checksum, normalize_text


@dataclass(frozen=True)
class CapabilitySpec:
    name: str
    base_risk: float
    always_human: bool
    max_actions: int
    max_ttl_seconds: int
    description: str


CAPABILITY_REGISTRY: dict[str, CapabilitySpec] = {
    spec.name: spec
    for spec in (
        CapabilitySpec("respond_in_chat", 0.05, False, 1000, 86400, "Reply inside the current conversation."),
        CapabilitySpec("read_public_data", 0.10, False, 200, 86400, "Read public web pages or open datasets."),
        CapabilitySpec("summarize_document", 0.15, False, 100, 86400, "Summarize a document the user supplied."),
        CapabilitySpec("draft_message", 0.30, False, 20, 7200, "Prepare a draft; never sends it."),
        CapabilitySpec("schedule_reminder", 0.30, False, 20, 86400, "Create a reminder for the operator."),
        CapabilitySpec("send_email", 0.70, True, 5, 3600, "Send an email to an external recipient."),
        CapabilitySpec("post_public", 0.80, True, 3, 3600, "Publish content publicly."),
        CapabilitySpec("write_sandbox_file", 0.50, True, 10, 3600, "Write a file inside a sandbox directory."),
    )
}

# Capabilities that no personality can ever enable, whatever it declares.
NEVER_GRANTABLE: frozenset[str] = frozenset(
    {
        "modify_safety_policy",
        "modify_own_personality",
        "modify_tool_policy",
        "grant_capability",
        "approve_own_action",
        "disable_audit_log",
        "delete_audit_log",
        "spend_money",
        "send_money",
        "delete_files",
        "access_private_data",
        "execute_code",
    }
)

# Always merged into the compiled safety policy; a persona cannot remove them.
MANDATORY_FORBIDDEN_ACTIONS: tuple[str, ...] = (
    "send money",
    "delete files",
    "access private data",
    "modify own safety policy",
    "modify own personality",
    "make medical claims",
    "impersonate a real person",
)
MANDATORY_ESCALATIONS: tuple[str, ...] = (
    "external communications",
    "financial actions",
    "file deletion",
    "public posting",
)

DEFAULT_CONTEXTS: tuple[str, ...] = ("general",)


class PolicyError(ValueError):
    """Raised when a manifest's policy cannot be compiled."""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def _merge_unique(mandatory: tuple[str, ...], declared: list[str]) -> list[str]:
    seen: dict[str, str] = {}
    for item in list(mandatory) + list(declared):
        key = normalize_text(item)
        if key and key not in seen:
            seen[key] = item
    return list(seen.values())


def compile_policy(manifest: dict[str, Any]) -> dict[str, Any]:
    """Compile a schema-checked manifest into an effective, clamped runtime policy.

    Returns {"capabilities": {...}, "safety": {...}, "notes": [...], "policy_hash": ...}.
    Raises PolicyError for unknown or never-grantable capabilities.
    """
    modules = manifest["modules"]
    declared = modules["tool_policy"]["capabilities"]
    errors: list[str] = []
    notes: list[str] = []
    caps: dict[str, Any] = {}

    for name, decl in declared.items():
        if name in NEVER_GRANTABLE:
            if decl.get("enabled"):
                errors.append(f"capability {name!r} can never be enabled by a personality")
            else:
                notes.append(f"{name}: declared disabled (never grantable anyway)")
            continue
        spec = CAPABILITY_REGISTRY.get(name)
        if spec is None:
            errors.append(f"unknown capability {name!r} (not in the runtime registry)")
            continue
        if not decl.get("enabled"):
            continue
        requires_human = bool(decl.get("requires_human_approval", False))
        if spec.always_human and not requires_human:
            notes.append(f"{name}: requires_human_approval forced to true by the runtime")
            requires_human = True
        max_actions = decl.get("max_actions", spec.max_actions)
        if max_actions > spec.max_actions:
            notes.append(f"{name}: max_actions clamped {max_actions} -> {spec.max_actions}")
            max_actions = spec.max_actions
        ttl = decl.get("lease_ttl_seconds", spec.max_ttl_seconds)
        if ttl > spec.max_ttl_seconds:
            notes.append(f"{name}: lease_ttl_seconds clamped {ttl} -> {spec.max_ttl_seconds}")
            ttl = spec.max_ttl_seconds
        contexts = sorted(set(decl.get("allowed_contexts") or DEFAULT_CONTEXTS))
        caps[name] = {
            "base_risk": spec.base_risk,
            "requires_human_approval": requires_human,
            "max_actions": max_actions,
            "lease_ttl_seconds": ttl,
            "allowed_contexts": contexts,
        }

    if errors:
        raise PolicyError(errors)

    safety_decl = modules["safety_policy"]
    safety = {
        "forbidden_actions": _merge_unique(MANDATORY_FORBIDDEN_ACTIONS, safety_decl.get("forbidden_actions", [])),
        "escalation_required_for": _merge_unique(MANDATORY_ESCALATIONS, safety_decl.get("escalation_required_for", [])),
        "claims_to_avoid": list(safety_decl.get("claims_to_avoid", [])),
        "myths_to_correct": list(safety_decl.get("myths_to_correct", [])),
    }
    compiled = {"capabilities": caps, "safety": safety, "notes": notes}
    compiled["policy_hash"] = checksum({"capabilities": caps, "safety": safety})
    return compiled
