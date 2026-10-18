"""IdentityRuntime: governed, reversible personality versions with leased capabilities.

Lifecycle of a personality:

    upload -> validate -> compile policy -> shadow simulation
           -> pending (auto modules approved, protected modules wait)
           -> human approvals (quorum modules need two distinct people)
           -> commit (previous version kept; its leases revoked)
           -> rollback restores any previously committed version

Lifecycle of an action:

    human grants a lease -> avatar requests an action
        -> denied (no lease, wrong context, not in policy, never grantable)
        -> held for a human (policy says so, or the OES-61440 tripwire fires)
        -> authorised autonomously (lease consumed once, proof recorded)
    held action -> approve_action (lease consumed once) or reject_action

The runtime authorises and records. It does not perform the action itself:
the host application executes an action only when it holds a proof whose
hash is in the ledger.
"""

from __future__ import annotations

import math
import os
import re
import time
from typing import Any, Callable

from . import fabric
from .ledger import HashChainLedger, LedgerIntegrityError
from .policy import NEVER_GRANTABLE, PolicyError, compile_policy
from .schema import validate_manifest
from .signing import verify as verify_token
from .simulation import ModelHook, ShadowSimulation
from .store import Store, StoreError
from .util import checksum, frozen_copy, sha256_hex

AUTO_MODULES = ("voice", "appearance")
QUORUM_MODULES = ("tool_policy", "safety_policy")
QUORUM_SIZE = 2
APPROVER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$")
RESERVED_APPROVER_PREFIXES = ("avatar", "runtime", "system", "self")
PROOF_VERSION = "identity-runtime/proof-v1"
# Explicit rule, independent of the fabric: at or above this effective risk an
# action is never authorised without a human.
AUTONOMY_RISK_CEILING = 0.5


class RuntimeErrorBase(RuntimeError):
    pass


class UnknownAvatar(RuntimeErrorBase):
    pass


class ApprovalError(RuntimeErrorBase):
    pass


class LeaseError(RuntimeErrorBase):
    pass


class ActionError(RuntimeErrorBase):
    pass


def required_approvals(modules: dict[str, Any]) -> dict[str, int]:
    req = {}
    for name in modules:
        if name in AUTO_MODULES:
            req[name] = 0
        elif name in QUORUM_MODULES:
            req[name] = QUORUM_SIZE
        else:
            req[name] = 1
    return req


class IdentityRuntime:
    def __init__(
        self,
        state_dir: str | None = None,
        *,
        clock: Callable[[], int] | None = None,
        model_hook: ModelHook | None = None,
        approver_keys: dict[str, bytes] | None = None,
    ):
        self.clock = clock or time.time_ns
        self.store = Store(state_dir)
        self.ledger = HashChainLedger(self.store.ledger_path, clock=self.clock)
        self.ledger.check_head(self.store.state.get("ledger_head"))
        self.simulation = ShadowSimulation(model_hook)
        self.approver_keys = approver_keys
        self._counter = 0

    # ------------------------------------------------------------------ helpers
    @property
    def _avatars(self) -> dict[str, Any]:
        return self.store.state["avatars"]

    def _avatar(self, avatar_id: str) -> dict[str, Any]:
        av = self._avatars.get(avatar_id)
        if av is None:
            raise UnknownAvatar(f"unknown avatar {avatar_id!r}")
        return av

    def _log(self, event: str, identity_root: str | None, payload: dict[str, Any]) -> dict[str, Any]:
        entry = self.ledger.append(event, identity_root, payload)
        self.store.state["ledger_head"] = self.ledger.head()
        return entry

    def _commit_state(self) -> None:
        self.store.save_state()

    def _new_id(self, prefix: str, *parts: str) -> str:
        self._counter += 1
        material = "|".join([prefix, *parts, str(self.clock()), str(self._counter), os.urandom(16).hex()])
        return f"{prefix}-{sha256_hex(material)[:24]}"

    def _require_writable(self) -> None:
        if self.ledger.broken:
            raise LedgerIntegrityError(f"ledger is broken, runtime is read-only: {self.ledger.broken}")

    def _check_approver(self, avatar_id: str, approver: str, kind: str, subject: str, detail: str, signature: str | None) -> None:
        if not isinstance(approver, str) or not APPROVER_RE.match(approver):
            raise ApprovalError(f"invalid approver id {approver!r}")
        lowered = approver.casefold()
        if any(lowered == p or lowered.startswith(p + ":") or lowered.startswith(p + "-") for p in RESERVED_APPROVER_PREFIXES):
            raise ApprovalError(f"approver id {approver!r} uses a reserved prefix")
        if lowered in {a.casefold() for a in self._avatars}:
            raise ApprovalError("an avatar cannot approve (itself or any other avatar)")
        av = self._avatars.get(avatar_id)
        if av and lowered == av["identity_root"].casefold():
            raise ApprovalError("the identity root cannot approve")
        if self.approver_keys is not None:
            key = self.approver_keys.get(approver)
            if key is None:
                raise ApprovalError(f"approver {approver!r} is not in the keyring")
            if not verify_token(key, signature, kind, avatar_id, subject, detail, approver):
                raise ApprovalError("approval token does not verify")

    def _load_version(self, manifest_checksum: str) -> dict[str, Any]:
        record = self.store.get_version(manifest_checksum)
        compiled = compile_policy(record["manifest"])  # recompute; never trust the stored copy
        if compiled["policy_hash"] != record["compiled"]["policy_hash"]:
            raise StoreError("stored compiled policy does not match the manifest")
        record["compiled"] = compiled
        return record

    def _revoke_all(self, av: dict[str, Any], reason: str) -> list[str]:
        revoked = []
        for lease in av["leases"].values():
            if not lease["revoked"]:
                lease["revoked"] = True
                lease["revoked_reason"] = reason
                revoked.append(lease["lease_id"])
        for action in av["actions"].values():
            if action["status"] == "held":
                action["status"] = "cancelled"
                action["cancel_reason"] = reason
        return revoked

    # ------------------------------------------------------------ personality
    def validate(self, manifest: Any) -> dict[str, Any]:
        """Dry run: schema, policy compile and simulation, with no state change."""
        errors = validate_manifest(manifest)
        if errors:
            return {"status": "rejected", "stage": "schema", "errors": errors}
        try:
            compiled = compile_policy(manifest)
        except PolicyError as exc:
            report = self.simulation.run(manifest, None)
            # Text findings add context; capability findings repeat the policy errors.
            text = [f"{f['kind']} at {f['path']}" for f in report.findings if f["pattern"] != "never-grantable capability enabled"]
            return {"status": "rejected", "stage": "policy", "errors": exc.errors + text, "simulation": report.to_dict()}
        report = self.simulation.run(manifest, compiled)
        if not report.passed:
            return {"status": "rejected", "stage": "simulation", "errors": [f"{f['kind']} at {f['path']}" for f in report.findings] + [f"probe failed: {p['prompt']}" for p in report.probes if not p["passed"]], "simulation": report.to_dict()}
        return {"status": "valid", "manifest_checksum": checksum(manifest), "compiled": compiled, "simulation": report.to_dict()}

    def receive_personality(self, manifest: Any) -> dict[str, Any]:
        self._require_writable()
        manifest = frozen_copy(manifest) if isinstance(manifest, (dict, list)) else manifest
        result = self.validate(manifest)
        avatar_id = manifest.get("avatar_id") if isinstance(manifest, dict) else None
        if result["status"] != "valid":
            root = self._avatars.get(avatar_id, {}).get("identity_root") if isinstance(avatar_id, str) else None
            self._log("personality_rejected", root, {"avatar_id": avatar_id if isinstance(avatar_id, str) else None, "stage": result["stage"], "errors": result["errors"], "manifest_checksum": checksum(manifest) if isinstance(manifest, dict) else None})
            self._commit_state()
            return result

        mc = result["manifest_checksum"]
        av = self._avatars.get(avatar_id)
        if av is None:
            created = int(self.clock())
            root = sha256_hex(f"identity-root/1|{avatar_id}|{created}|{os.urandom(16).hex()}")
            av = {"identity_root": root, "created_ns": created, "active": None, "history": [], "committed": [], "pending": {}, "leases": {}, "actions": {}, "halted": False}
            self._avatars[avatar_id] = av
            self._log("identity_root_created", root, {"avatar_id": avatar_id})
        if av["active"] == mc:
            return {"status": "already_active", "manifest_checksum": mc, "identity_root": av["identity_root"]}
        if mc not in av["pending"]:
            self.store.put_version(mc, {"manifest": manifest, "compiled": result["compiled"], "simulation": result["simulation"]})
            req = required_approvals(manifest["modules"])
            approvals = {m: [] for m in req}
            for m, n in req.items():
                if n == 0:
                    approvals[m] = ["runtime:auto"]
            av["pending"][mc] = {"received_ns": int(self.clock()), "required": req, "approvals": approvals}
            self._log("personality_received", av["identity_root"], {
                "avatar_id": avatar_id, "manifest_checksum": mc, "policy_hash": result["compiled"]["policy_hash"],
                "module_checksums": {m: checksum(b) for m, b in manifest["modules"].items()},
                "auto_approved": [m for m, n in req.items() if n == 0], "policy_notes": result["compiled"]["notes"],
            })
            self._commit_state()
        pending = av["pending"][mc]
        return {
            "status": "pending_approval",
            "avatar_id": avatar_id,
            "identity_root": av["identity_root"],
            "manifest_checksum": mc,
            "policy_hash": result["compiled"]["policy_hash"],
            "policy_notes": result["compiled"]["notes"],
            "awaiting": self._awaiting(pending),
            "simulation": result["simulation"],
        }

    @staticmethod
    def _awaiting(pending: dict[str, Any]) -> dict[str, int]:
        out = {}
        for m, n in pending["required"].items():
            humans = [a for a in pending["approvals"][m] if a != "runtime:auto"]
            if n and len(humans) < n:
                out[m] = n - len(humans)
        return out

    def approve_module(self, avatar_id: str, manifest_checksum: str, module_type: str, approver_id: str, signature: str | None = None) -> dict[str, Any]:
        self._require_writable()
        av = self._avatar(avatar_id)
        pending = av["pending"].get(manifest_checksum)
        if pending is None:
            raise ApprovalError(f"no pending version {manifest_checksum[:12]} for {avatar_id!r}")
        if module_type not in pending["required"]:
            raise ApprovalError(f"module {module_type!r} is not in this manifest")
        if pending["required"][module_type] == 0:
            return {"status": "auto_approved", "module": module_type, "awaiting": self._awaiting(pending)}
        self._check_approver(avatar_id, approver_id, "module", manifest_checksum, module_type, signature)
        approvers = pending["approvals"][module_type]
        if approver_id.casefold() in {a.casefold() for a in approvers}:
            raise ApprovalError(f"{approver_id!r} already approved {module_type!r}; quorum needs distinct people")
        approvers.append(approver_id)
        self._log("module_approved", av["identity_root"], {"avatar_id": avatar_id, "manifest_checksum": manifest_checksum, "module": module_type, "approver": approver_id, "signed": signature is not None})
        awaiting = self._awaiting(pending)
        result = {"status": "approved", "module": module_type, "awaiting": awaiting}
        if not awaiting:
            result["commit"] = self._commit(avatar_id, av, manifest_checksum)
            result["status"] = "committed"
        self._commit_state()
        return result

    def _commit(self, avatar_id: str, av: dict[str, Any], mc: str) -> dict[str, Any]:
        record = self._load_version(mc)
        previous = av["active"]
        revoked = self._revoke_all(av, "identity_commit")
        if previous:
            av["history"].append(previous)
        av["active"] = mc
        if mc not in av["committed"]:
            av["committed"].append(mc)
        approvals = av["pending"].pop(mc)["approvals"]
        self._log("identity_committed", av["identity_root"], {"avatar_id": avatar_id, "manifest_checksum": mc, "previous": previous, "policy_hash": record["compiled"]["policy_hash"], "approvals": approvals, "revoked_leases": revoked})
        return {"active": mc, "previous": previous, "revoked_leases": revoked}

    def rollback(self, avatar_id: str, approver_id: str, to_checksum: str | None = None, reason: str = "", signature: str | None = None) -> dict[str, Any]:
        self._require_writable()
        av = self._avatar(avatar_id)
        current = av["active"]
        if to_checksum is None:
            if not av["history"]:
                raise ApprovalError("no earlier committed version to roll back to")
            to_checksum = av["history"][-1]
        if to_checksum not in av["committed"]:
            raise ApprovalError("can only roll back to a version this avatar has committed before")
        if to_checksum == current:
            raise ApprovalError("that version is already active")
        self._check_approver(avatar_id, approver_id, "rollback", to_checksum, current or "", signature)
        self._load_version(to_checksum)  # raises if missing or tampered
        revoked = self._revoke_all(av, "rollback")
        if to_checksum in av["history"]:
            av["history"].remove(to_checksum)
        if current:
            av["history"].append(current)
        av["active"] = to_checksum
        self._log("identity_rolled_back", av["identity_root"], {"avatar_id": avatar_id, "from": current, "to": to_checksum, "approver": approver_id, "reason": reason, "revoked_leases": revoked})
        self._commit_state()
        return {"status": "rolled_back", "active": to_checksum, "previous": current, "revoked_leases": revoked}

    # ------------------------------------------------------------------ leases
    def grant_lease(self, avatar_id: str, capability: str, approver_id: str, max_actions: int | None = None, ttl_seconds: int | None = None, signature: str | None = None) -> dict[str, Any]:
        self._require_writable()
        av = self._avatar(avatar_id)
        if av["halted"]:
            raise LeaseError("avatar is halted; clear the halt first")
        if not av["active"]:
            raise LeaseError("avatar has no committed identity")
        if capability in NEVER_GRANTABLE:
            raise LeaseError(f"{capability!r} can never be leased")
        compiled = self._load_version(av["active"])["compiled"]
        cap = compiled["capabilities"].get(capability)
        if cap is None:
            raise LeaseError(f"{capability!r} is not enabled in the active personality's compiled policy")
        self._check_approver(avatar_id, approver_id, "lease", av["active"], capability, signature)
        n = cap["max_actions"] if max_actions is None else max(1, min(int(max_actions), cap["max_actions"]))
        ttl = cap["lease_ttl_seconds"] if ttl_seconds is None else max(1, min(int(ttl_seconds), cap["lease_ttl_seconds"]))
        now = int(self.clock())
        lease_id = self._new_id("lease", av["identity_root"], capability)
        lease = {
            "lease_id": lease_id, "capability": capability, "version": av["active"], "policy_hash": compiled["policy_hash"],
            "issued_ns": now, "expires_ns": now + ttl * 1_000_000_000, "max_actions": n, "used": 0, "reserved": 0,
            "requires_human_approval": cap["requires_human_approval"], "allowed_contexts": cap["allowed_contexts"],
            "granted_by": approver_id, "revoked": False,
        }
        av["leases"][lease_id] = lease
        self._log("lease_granted", av["identity_root"], {"avatar_id": avatar_id, **lease})
        self._commit_state()
        return frozen_copy(lease)

    def _lease_valid(self, av: dict[str, Any], lease: dict[str, Any]) -> str | None:
        if lease["revoked"]:
            return "revoked"
        if lease["version"] != av["active"]:
            return "bound_to_other_version"
        if int(self.clock()) >= lease["expires_ns"]:
            return "expired"
        return None

    def revoke_capability(self, avatar_id: str, capability: str, reason: str = "", by: str = "operator") -> dict[str, Any]:
        self._require_writable()
        av = self._avatar(avatar_id)
        revoked = []
        for lease in av["leases"].values():
            if lease["capability"] == capability and not lease["revoked"]:
                lease["revoked"] = True
                lease["revoked_reason"] = reason
                revoked.append(lease["lease_id"])
        cancelled = []
        for action in av["actions"].values():
            if action["status"] == "held" and action["lease_id"] in revoked:
                action["status"] = "cancelled"
                action["cancel_reason"] = "lease_revoked"
                cancelled.append(action["action_id"])
        self._log("capability_revoked", av["identity_root"], {"avatar_id": avatar_id, "capability": capability, "reason": reason, "by": by, "revoked_leases": revoked, "cancelled_actions": cancelled})
        self._commit_state()
        return {"status": "revoked", "capability": capability, "revoked_leases": revoked, "cancelled_actions": cancelled}

    # ----------------------------------------------------------------- actions
    def request_action(self, avatar_id: str, capability: str, context: str = "general", risk: float = 0.0, description: str = "") -> dict[str, Any]:
        self._require_writable()
        av = self._avatar(avatar_id)
        root = av["identity_root"]
        try:
            declared = float(risk)
        except (TypeError, ValueError):
            declared = 1.0
        if not math.isfinite(declared):
            declared = 1.0
        declared = min(1.0, max(0.0, declared))

        def deny(reason: str) -> dict[str, Any]:
            entry = self._log("action_denied", root, {"avatar_id": avatar_id, "capability": capability, "context": context, "reason": reason, "description": description})
            self._commit_state()
            return {"decision": "denied", "reason": reason, "ledger_seq": entry["seq"]}

        if av["halted"]:
            return deny("avatar_halted")
        if not av["active"]:
            return deny("no_committed_identity")
        if capability in NEVER_GRANTABLE:
            return deny("never_grantable_capability")
        compiled = self._load_version(av["active"])["compiled"]
        cap = compiled["capabilities"].get(capability)
        if cap is None:
            return deny("capability_not_in_policy")
        if context not in cap["allowed_contexts"]:
            return deny("context_not_allowed")
        leases = [l for l in av["leases"].values() if l["capability"] == capability and self._lease_valid(av, l) is None and l["used"] + l["reserved"] < l["max_actions"]]
        if not leases:
            return deny("no_valid_lease")
        lease = max(leases, key=lambda l: l["issued_ns"])

        effective = max(declared, cap["base_risk"])
        utilisation = (lease["used"] + lease["reserved"]) / lease["max_actions"]
        fab = fabric.evaluate(effective, cap["base_risk"], 0.0, utilisation)
        fab_summary = {k: fab[k] for k in ("fabric", "tripped_channels", "tripped_membranes", "tripped_supervisors", "tripped_sectors", "checkpoint", "halt")}

        if fab["halt"]:
            av["halted"] = True
            revoked = self._revoke_all(av, "fabric_halt")
            entry = self._log("avatar_halted", root, {"avatar_id": avatar_id, "capability": capability, "effective_risk": effective, "fabric": fab_summary, "revoked_leases": revoked})
            self._commit_state()
            return {"decision": "halted", "reason": "oes61440_halt", "fabric": fab_summary, "ledger_seq": entry["seq"]}

        reasons = []
        if cap["requires_human_approval"]:
            reasons.append("policy_requires_human")
        if effective >= AUTONOMY_RISK_CEILING:
            reasons.append("risk_at_or_above_autonomy_ceiling")
        if fab["checkpoint"]:
            reasons.append("oes61440_checkpoint")
        action_id = self._new_id("action", root, capability)
        proof = {
            "proof_version": PROOF_VERSION, "action_id": action_id, "avatar_id": avatar_id, "identity_root": root,
            "manifest_checksum": av["active"], "policy_hash": compiled["policy_hash"], "lease_id": lease["lease_id"],
            "capability": capability, "context": context, "description": description,
            "declared_risk": declared, "effective_risk": effective, "fabric": fab_summary,
        }
        if reasons:
            lease["reserved"] += 1
            av["actions"][action_id] = {"action_id": action_id, "status": "held", "reasons": reasons, "lease_id": lease["lease_id"], "proof": proof}
            entry = self._log("action_held", root, {"avatar_id": avatar_id, "action_id": action_id, "reasons": reasons, "proof": proof})
            self._commit_state()
            return {"decision": "held_for_human", "action_id": action_id, "reasons": reasons, "fabric": fab_summary, "ledger_seq": entry["seq"]}

        lease["used"] += 1
        proof["decision"] = "authorised_autonomously"
        proof["proof_hash"] = checksum(proof)
        av["actions"][action_id] = {"action_id": action_id, "status": "authorised", "reasons": [], "lease_id": lease["lease_id"], "proof": proof}
        entry = self._log("action_authorised", root, {"avatar_id": avatar_id, "action_id": action_id, "proof": proof})
        self._commit_state()
        return {"decision": "authorised_autonomously", "action_id": action_id, "proof": proof, "lease_remaining": lease["max_actions"] - lease["used"] - lease["reserved"], "ledger_seq": entry["seq"]}

    def _find_action(self, action_id: str) -> tuple[str, dict[str, Any], dict[str, Any]]:
        for avatar_id, av in self._avatars.items():
            if action_id in av["actions"]:
                return avatar_id, av, av["actions"][action_id]
        raise ActionError(f"unknown action {action_id!r}")

    def approve_action(self, action_id: str, approver_id: str, signature: str | None = None) -> dict[str, Any]:
        self._require_writable()
        avatar_id, av, action = self._find_action(action_id)
        if action["status"] != "held":
            raise ActionError(f"action is {action['status']}, not held")
        self._check_approver(avatar_id, approver_id, "action", action_id, action["proof"]["capability"], signature)
        lease = av["leases"][action["lease_id"]]
        problem = self._lease_valid(av, lease)
        if problem:
            lease["reserved"] = max(0, lease["reserved"] - 1)
            action["status"] = "cancelled"
            action["cancel_reason"] = f"lease_{problem}"
            self._log("action_cancelled", av["identity_root"], {"avatar_id": avatar_id, "action_id": action_id, "reason": action["cancel_reason"]})
            self._commit_state()
            raise ActionError(f"lease is {problem}; action cancelled")
        lease["reserved"] -= 1
        lease["used"] += 1
        proof = dict(action["proof"])
        proof["decision"] = "authorised_by_human"
        proof["approved_by"] = approver_id
        proof["proof_hash"] = checksum(proof)
        action["proof"] = proof
        action["status"] = "authorised"
        entry = self._log("action_authorised", av["identity_root"], {"avatar_id": avatar_id, "action_id": action_id, "proof": proof})
        self._commit_state()
        return {"decision": "authorised_by_human", "action_id": action_id, "proof": proof, "ledger_seq": entry["seq"]}

    def reject_action(self, action_id: str, approver_id: str, reason: str = "", signature: str | None = None) -> dict[str, Any]:
        self._require_writable()
        avatar_id, av, action = self._find_action(action_id)
        if action["status"] != "held":
            raise ActionError(f"action is {action['status']}, not held")
        self._check_approver(avatar_id, approver_id, "reject", action_id, action["proof"]["capability"], signature)
        lease = av["leases"][action["lease_id"]]
        lease["reserved"] = max(0, lease["reserved"] - 1)
        action["status"] = "rejected"
        self._log("action_rejected", av["identity_root"], {"avatar_id": avatar_id, "action_id": action_id, "approver": approver_id, "reason": reason})
        self._commit_state()
        return {"decision": "rejected", "action_id": action_id}

    def clear_halt(self, avatar_id: str, approver_id: str, reason: str = "", signature: str | None = None) -> dict[str, Any]:
        self._require_writable()
        av = self._avatar(avatar_id)
        if not av["halted"]:
            return {"status": "not_halted"}
        self._check_approver(avatar_id, approver_id, "clear_halt", av["identity_root"], "", signature)
        av["halted"] = False
        self._log("halt_cleared", av["identity_root"], {"avatar_id": avatar_id, "approver": approver_id, "reason": reason})
        self._commit_state()
        return {"status": "cleared"}

    # ------------------------------------------------------------------ reading
    def verify_proof(self, proof: dict[str, Any]) -> bool:
        body = {k: v for k, v in proof.items() if k != "proof_hash"}
        if checksum(body) != proof.get("proof_hash"):
            return False
        return any(e["payload"].get("proof", {}).get("proof_hash") == proof["proof_hash"] for e in self.ledger.find("action_authorised"))

    def verify(self) -> dict[str, Any]:
        result = self.ledger.verify_chain()
        if result["valid"]:
            self.ledger.check_head(self.store.state.get("ledger_head"))
            if self.ledger.broken:
                result = {"valid": False, "entries": result["entries"], "reason": self.ledger.broken}
        return result

    def current_identity(self, avatar_id: str) -> dict[str, Any]:
        av = self._avatar(avatar_id)
        out = {"avatar_id": avatar_id, "identity_root": av["identity_root"], "active": av["active"], "halted": av["halted"], "history": list(av["history"]), "pending": {mc: self._awaiting(p) for mc, p in av["pending"].items()}}
        if av["active"]:
            record = self._load_version(av["active"])
            ident = record["manifest"]["modules"]["identity"]
            out["display_name"] = record["manifest"]["display_name"]
            out["character_type"] = ident["character_type"]
            out["disclaimer"] = ident.get("disclaimer")
            out["capabilities"] = record["compiled"]["capabilities"]
        out["leases"] = [
            {"lease_id": l["lease_id"], "capability": l["capability"], "used": l["used"], "reserved": l["reserved"], "max_actions": l["max_actions"], "state": self._lease_valid(av, l) or "valid"}
            for l in av["leases"].values()
        ]
        out["held_actions"] = [a["action_id"] for a in av["actions"].values() if a["status"] == "held"]
        return out

    def status(self) -> dict[str, Any]:
        return {"avatars": {a: self.current_identity(a) for a in sorted(self._avatars)}, "ledger": self.verify()}
