"""Command-line interface: python -m identity_runtime <command> ..."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from typing import Any

from . import __version__
from .runtime import ApprovalError, IdentityRuntime, RuntimeErrorBase
from .ledger import LedgerIntegrityError
from .signing import lease_detail, load_keyring, module_detail, new_key, new_nonce, rollback_detail, save_keyring, sign
from .store import StoreError

DEFAULT_STATE = os.environ.get("IDENTITY_RUNTIME_STATE", ".identity-runtime")


def _print(obj: Any) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def _load_json(path: str) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _runtime(args: argparse.Namespace) -> IdentityRuntime:
    keys = load_keyring(args.keyring) if args.keyring else None
    return IdentityRuntime(args.state, approver_keys=keys)


def _token(args: argparse.Namespace, kind: str, avatar_id: str, subject: str, detail: str) -> str | None:
    if not args.keyring:
        return None
    keys = load_keyring(args.keyring)
    key = keys.get(args.approver)
    return sign(key, kind, avatar_id, subject, detail, args.approver) if key else None


def _resolve_checksum(rt: IdentityRuntime, avatar_id: str, prefix: str | None) -> str:
    pending = list(rt.current_identity(avatar_id)["pending"])
    if prefix:
        matches = [c for c in pending if c.startswith(prefix)]
    else:
        matches = pending
    if len(matches) != 1:
        raise ApprovalError(f"expected exactly one pending version, found {len(matches)}; pass --checksum")
    return matches[0]


def cmd_validate(args):
    rt = IdentityRuntime(None)
    result = rt.validate(_load_json(args.file))
    if not args.verbose:
        result.pop("compiled", None)
    _print(result)
    return 0 if result["status"] == "valid" else 2


def cmd_upload(args):
    rt = _runtime(args)
    result = rt.receive_personality(_load_json(args.file))
    if not args.verbose:
        result.pop("simulation", None)
    _print(result)
    return 0 if result["status"] in ("pending_approval", "already_active") else 2


def cmd_approve(args):
    rt = _runtime(args)
    mc = _resolve_checksum(rt, args.avatar, args.checksum)
    modules = args.module
    if modules == ["all"]:
        modules = list(rt.current_identity(args.avatar)["pending"][mc])
    proposal_id = rt.current_identity(args.avatar)["proposal_ids"].get(mc, "")
    out = []
    for module in modules:
        token = _token(args, "module", args.avatar, mc, module_detail(module, proposal_id))
        out.append(rt.approve_module(args.avatar, mc, module, args.approver, signature=token))
    _print(out)
    return 0


def cmd_grant(args):
    rt = _runtime(args)
    terms = rt.lease_terms(args.avatar, args.capability, args.max_actions, args.ttl)
    nonce = new_nonce() if args.keyring else None
    token = _token(args, "lease", args.avatar, terms["version"], lease_detail(terms, nonce or ""))
    _print(rt.grant_lease(args.avatar, args.capability, args.approver, args.max_actions, args.ttl, signature=token, nonce=nonce))
    return 0


def cmd_act(args):
    rt = _runtime(args)
    result = rt.request_action(args.avatar, args.capability, args.context, args.risk, args.description)
    _print(result)
    return 0 if result["decision"] != "denied" else 3


def cmd_approve_action(args):
    rt = _runtime(args)
    _, _, action = rt._find_action(args.action_id)
    token = _token(args, "action", action["proof"]["avatar_id"], args.action_id, action["proof"]["capability"])
    _print(rt.approve_action(args.action_id, args.approver, signature=token))
    return 0


def _stored_proof(rt: IdentityRuntime, action_id: str) -> dict:
    _, _, action = rt._find_action(action_id)
    if "proof_hash" not in action["proof"]:
        raise ApprovalError(f"action {action_id} has no authorised proof (status {action['status']})")
    return action["proof"]


def cmd_check_proof(args):
    rt = _runtime(args)
    result = rt.check_proof(_stored_proof(rt, args.action_id))
    _print(result)
    return 0 if result["valid"] else 5


def cmd_redeem(args):
    rt = _runtime(args)
    result = rt.redeem_proof(_stored_proof(rt, args.action_id), by=args.by)
    _print(result)
    return 0 if result["status"] == "redeemed" else 5


def cmd_reject_action(args):
    rt = _runtime(args)
    _, _, action = rt._find_action(args.action_id)
    token = _token(args, "reject", action["proof"]["avatar_id"], args.action_id, action["proof"]["capability"])
    _print(rt.reject_action(args.action_id, args.approver, args.reason, signature=token))
    return 0


def cmd_revoke(args):
    rt = _runtime(args)
    _print(rt.revoke_capability(args.avatar, args.capability, args.reason, by=args.by))
    return 0


def cmd_rollback(args):
    rt = _runtime(args)
    ident = rt.current_identity(args.avatar)
    target = args.to or (ident["history"][-1] if ident["history"] else "")
    nonce = new_nonce() if args.keyring else None
    token = _token(args, "rollback", args.avatar, target, rollback_detail(ident["active"] or "", nonce or ""))
    _print(rt.rollback(args.avatar, args.approver, args.to, args.reason, signature=token, nonce=nonce))
    return 0


def cmd_clear_halt(args):
    rt = _runtime(args)
    halt_id = rt.current_identity(args.avatar)["halt_id"] or ""
    token = _token(args, "clear_halt", args.avatar, halt_id, "")
    _print(rt.clear_halt(args.avatar, args.approver, args.reason, signature=token))
    return 0


def cmd_status(args):
    rt = _runtime(args)
    _print(rt.current_identity(args.avatar) if args.avatar else rt.status())
    return 0


def cmd_verify(args):
    rt = IdentityRuntime(args.state)
    result = rt.verify()
    _print(result)
    return 0 if result["valid"] else 4


def cmd_keygen(args):
    keys = load_keyring(args.keyring) if os.path.exists(args.keyring) else {}
    for name in args.approvers:
        keys[name] = new_key()
    save_keyring(args.keyring, keys)
    _print({"keyring": args.keyring, "approvers": sorted(keys)})
    return 0


def cmd_demo(args):
    from .demo import run_demo

    state = args.state_dir or tempfile.mkdtemp(prefix="identity-runtime-demo-")
    _print(run_demo(state, args.personality))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="identity_runtime", description="Governed avatar personalities with leased capabilities (research prototype).")
    p.add_argument("--version", action="version", version=f"identity-runtime {__version__}")
    p.add_argument("--state", default=DEFAULT_STATE, help="state directory (default: $IDENTITY_RUNTIME_STATE or .identity-runtime)")
    p.add_argument("--keyring", default=os.environ.get("IDENTITY_RUNTIME_KEYRING"), help="approver keyring JSON; when set, every approval is HMAC-signed and checked")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("validate", help="dry-run checks on a personality file, no state change")
    s.add_argument("file"); s.add_argument("-v", "--verbose", action="store_true"); s.set_defaults(func=cmd_validate)

    s = sub.add_parser("upload", help="upload a personality; it waits for approvals")
    s.add_argument("file"); s.add_argument("-v", "--verbose", action="store_true"); s.set_defaults(func=cmd_upload)

    s = sub.add_parser("approve", help="approve one or more modules of a pending version")
    s.add_argument("avatar"); s.add_argument("module", nargs="+", help="module names, or 'all'")
    s.add_argument("--as", dest="approver", required=True); s.add_argument("--checksum"); s.set_defaults(func=cmd_approve)

    s = sub.add_parser("grant", help="grant a capability lease")
    s.add_argument("avatar"); s.add_argument("capability"); s.add_argument("--as", dest="approver", required=True)
    s.add_argument("--max-actions", type=int); s.add_argument("--ttl", type=int, help="seconds"); s.set_defaults(func=cmd_grant)

    s = sub.add_parser("act", help="request an action as the avatar")
    s.add_argument("avatar"); s.add_argument("capability"); s.add_argument("--context", default="general")
    s.add_argument("--risk", type=float, default=0.0); s.add_argument("--description", default=""); s.set_defaults(func=cmd_act)

    s = sub.add_parser("approve-action", help="approve a held action (consumes the lease once)")
    s.add_argument("action_id"); s.add_argument("--as", dest="approver", required=True); s.set_defaults(func=cmd_approve_action)

    s = sub.add_parser("check-proof", help="read-only: would this action's proof redeem right now?")
    s.add_argument("action_id"); s.set_defaults(func=cmd_check_proof)

    s = sub.add_parser("redeem", help="consume an authorised action's proof once, right before the host acts")
    s.add_argument("action_id"); s.add_argument("--by", default="host"); s.set_defaults(func=cmd_redeem)

    s = sub.add_parser("reject-action", help="reject a held action")
    s.add_argument("action_id"); s.add_argument("--as", dest="approver", required=True); s.add_argument("--reason", default=""); s.set_defaults(func=cmd_reject_action)

    s = sub.add_parser("revoke", help="revoke every lease for a capability")
    s.add_argument("avatar"); s.add_argument("capability"); s.add_argument("--reason", default=""); s.add_argument("--by", default="operator"); s.set_defaults(func=cmd_revoke)

    s = sub.add_parser("rollback", help="restore the previous (or a named) committed version")
    s.add_argument("avatar"); s.add_argument("--as", dest="approver", required=True); s.add_argument("--to"); s.add_argument("--reason", default=""); s.set_defaults(func=cmd_rollback)

    s = sub.add_parser("clear-halt", help="clear an OES-61440 halt")
    s.add_argument("avatar"); s.add_argument("--as", dest="approver", required=True); s.add_argument("--reason", default=""); s.set_defaults(func=cmd_clear_halt)

    s = sub.add_parser("status", help="show avatars, versions, leases and ledger state")
    s.add_argument("avatar", nargs="?"); s.set_defaults(func=cmd_status)

    s = sub.add_parser("verify", help="verify the hash-chained ledger")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("keygen", help="add HMAC approver keys to a keyring file (mode 600)")
    s.add_argument("keyring"); s.add_argument("approvers", nargs="+"); s.set_defaults(func=cmd_keygen)

    s = sub.add_parser("demo", help="run the scripted lifecycle demo in a fresh state directory")
    s.add_argument("--personality", default=None, help="path to a personality JSON (default: bundled Tesla-inspired example)")
    s.add_argument("--state-dir", default=None); s.set_defaults(func=cmd_demo)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (RuntimeErrorBase, LedgerIntegrityError, StoreError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
