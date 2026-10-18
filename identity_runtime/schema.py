"""Personality manifest validator (standard library only).

A small JSON-Schema-like checker. It reports every problem it finds instead
of stopping at the first one, so an uploader can fix a manifest in one pass.
"""

from __future__ import annotations

import re
from typing import Any

SCHEMA_ID = "identity-runtime/personality-v1"
AVATAR_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")
CONTEXT_RE = re.compile(r"^[a-z0-9_]{1,64}$")
MAX_STRING = 2000
MAX_MANIFEST_STRINGS = 2000

MODULE_TYPES = (
    "identity",
    "reasoning",
    "memory_policy",
    "tool_policy",
    "safety_policy",
    "interaction",
    "voice",
    "appearance",
)
REQUIRED_MODULES = ("identity", "tool_policy", "safety_policy", "interaction")

# field -> (type, required)
MODULE_FIELDS: dict[str, dict[str, tuple[type | tuple[type, ...], bool]]] = {
    "identity": {
        "name": (str, True),
        "role": (str, True),
        "description": (str, True),
        "character_type": (str, True),
        "inspired_by": (dict, False),
        "disclaimer": (str, False),
        "languages": (list, False),
    },
    "reasoning": {
        "style": (str, False),
        "principles": (list, False),
        "uncertainty_policy": (str, False),
    },
    "memory_policy": {
        "episodic_retention_days": (int, True),
        "store_personal_data": (bool, True),
        "learned_behaviour_updates": (str, False),
    },
    "tool_policy": {
        "capabilities": (dict, True),
    },
    "safety_policy": {
        "forbidden_actions": (list, True),
        "escalation_required_for": (list, True),
        "claims_to_avoid": (list, False),
        "myths_to_correct": (list, False),
    },
    "interaction": {
        "greeting": (str, True),
        "handoff_phrase": (str, True),
        "tone": (str, False),
        "audience": (str, False),
    },
    "voice": {
        "description": (str, False),
        "pace": (str, False),
        "synthetic_voice_label": (str, False),
    },
    "appearance": {
        "form": (str, False),
        "color_theme": (str, False),
        "visual_style": (str, False),
    },
}

CHARACTER_TYPES = ("original", "inspired_by_historical_figure", "mascot")
CAPABILITY_FIELDS = {
    "enabled": (bool, True),
    "requires_human_approval": (bool, False),
    "allowed_contexts": (list, False),
    "max_actions": (int, False),
    "lease_ttl_seconds": (int, False),
}


def _type_name(t: type | tuple[type, ...]) -> str:
    if isinstance(t, tuple):
        return " or ".join(x.__name__ for x in t)
    return t.__name__


def _is_type(value: Any, t: type | tuple[type, ...]) -> bool:
    # bool is a subclass of int; do not let True pass as an integer.
    if t is int:
        return isinstance(value, int) and not isinstance(value, bool)
    return isinstance(value, t)


def validate_manifest(manifest: Any) -> list[str]:
    """Return a list of human-readable errors; an empty list means valid."""
    errors: list[str] = []
    if not isinstance(manifest, dict):
        return ["manifest must be a JSON object"]

    allowed_top = {"schema", "avatar_id", "display_name", "manifest_version", "notes", "modules"}
    for key in manifest:
        if key not in allowed_top:
            errors.append(f"$.{key}: unknown top-level field")
    if manifest.get("schema") != SCHEMA_ID:
        errors.append(f"$.schema: must be {SCHEMA_ID!r}")
    avatar_id = manifest.get("avatar_id")
    if not isinstance(avatar_id, str) or not AVATAR_ID_RE.match(avatar_id):
        errors.append("$.avatar_id: must be 3-64 chars of lowercase letters, digits and hyphens")
    if not isinstance(manifest.get("display_name"), str) or not manifest.get("display_name", "").strip():
        errors.append("$.display_name: required non-empty string")
    if "manifest_version" in manifest and not isinstance(manifest["manifest_version"], str):
        errors.append("$.manifest_version: must be a string")

    modules = manifest.get("modules")
    if not isinstance(modules, dict):
        errors.append("$.modules: required object")
        return errors

    for name in modules:
        if name not in MODULE_TYPES:
            errors.append(f"$.modules.{name}: unknown module type")
    for name in REQUIRED_MODULES:
        if name not in modules:
            errors.append(f"$.modules.{name}: required module missing")

    for name, body in modules.items():
        if name not in MODULE_FIELDS:
            continue
        if not isinstance(body, dict):
            errors.append(f"$.modules.{name}: must be an object")
            continue
        spec = MODULE_FIELDS[name]
        for field, (ftype, required) in spec.items():
            if field not in body:
                if required:
                    errors.append(f"$.modules.{name}.{field}: required field missing")
                continue
            if not _is_type(body[field], ftype):
                errors.append(f"$.modules.{name}.{field}: must be {_type_name(ftype)}")
        for field in body:
            if field not in spec:
                errors.append(f"$.modules.{name}.{field}: unknown field")

    identity = modules.get("identity")
    if isinstance(identity, dict):
        ctype = identity.get("character_type")
        if isinstance(ctype, str) and ctype not in CHARACTER_TYPES:
            errors.append(f"$.modules.identity.character_type: must be one of {list(CHARACTER_TYPES)}")
        if ctype == "inspired_by_historical_figure":
            inspired = identity.get("inspired_by")
            if not isinstance(inspired, dict) or not isinstance(inspired.get("name"), str):
                errors.append("$.modules.identity.inspired_by.name: required for a character inspired by a historical figure")
            if not isinstance(inspired, dict) or not isinstance(inspired.get("lifespan"), str):
                errors.append("$.modules.identity.inspired_by.lifespan: required for a character inspired by a historical figure")
            disclaimer = identity.get("disclaimer")
            if not isinstance(disclaimer, str) or "not" not in disclaimer.casefold():
                errors.append("$.modules.identity.disclaimer: required and must state what the character is not")

    memory = modules.get("memory_policy")
    if isinstance(memory, dict):
        days = memory.get("episodic_retention_days")
        if _is_type(days, int) and not 0 <= days <= 365:
            errors.append("$.modules.memory_policy.episodic_retention_days: must be 0-365")

    tool_policy = modules.get("tool_policy")
    if isinstance(tool_policy, dict) and isinstance(tool_policy.get("capabilities"), dict):
        for cap, decl in tool_policy["capabilities"].items():
            base = f"$.modules.tool_policy.capabilities.{cap}"
            if not isinstance(decl, dict):
                errors.append(f"{base}: must be an object")
                continue
            for field, (ftype, required) in CAPABILITY_FIELDS.items():
                if field not in decl:
                    if required:
                        errors.append(f"{base}.{field}: required field missing")
                    continue
                if not _is_type(decl[field], ftype):
                    errors.append(f"{base}.{field}: must be {_type_name(ftype)}")
            for field in decl:
                if field not in CAPABILITY_FIELDS:
                    errors.append(f"{base}.{field}: unknown field")
            for ctx in decl.get("allowed_contexts", []) if isinstance(decl.get("allowed_contexts"), list) else []:
                if not isinstance(ctx, str) or not CONTEXT_RE.match(ctx):
                    errors.append(f"{base}.allowed_contexts: {ctx!r} must match {CONTEXT_RE.pattern}")
            for field in ("max_actions", "lease_ttl_seconds"):
                if _is_type(decl.get(field), int) and decl[field] < 1:
                    errors.append(f"{base}.{field}: must be >= 1")

    safety = modules.get("safety_policy")
    if isinstance(safety, dict):
        for field in ("forbidden_actions", "escalation_required_for", "claims_to_avoid", "myths_to_correct"):
            value = safety.get(field)
            if isinstance(value, list) and not all(isinstance(x, str) for x in value):
                errors.append(f"$.modules.safety_policy.{field}: every item must be a string")

    count = 0
    stack: list[Any] = [manifest]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            count += 1
            if len(item) > MAX_STRING:
                errors.append(f"string longer than {MAX_STRING} characters")
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, float) and item != item:
            errors.append("NaN is not allowed")
    if count > MAX_MANIFEST_STRINGS:
        errors.append(f"manifest has more than {MAX_MANIFEST_STRINGS} strings")
    return errors
