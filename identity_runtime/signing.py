"""Optional HMAC-SHA256 approval tokens (standard library only).

When the runtime is given an approver keyring, every human step (module
approval, lease grant, action approval, rollback, halt reset) must carry a
token computed with that approver's secret key over exactly what is being
approved. A token for one manifest, module or action does not verify for
another.

These are shared-secret MACs, not public-key signatures: whoever holds the
keyring can create tokens for every approver in it. Keep the keyring outside
the avatar's reach.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets

from .util import canonical_json


def approval_message(kind: str, avatar_id: str, subject: str, detail: str, approver: str) -> bytes:
    return canonical_json(
        {"v": 1, "kind": kind, "avatar_id": avatar_id, "subject": subject, "detail": detail, "approver": approver}
    ).encode("utf-8")


def sign(key: bytes, kind: str, avatar_id: str, subject: str, detail: str, approver: str) -> str:
    return hmac.new(key, approval_message(kind, avatar_id, subject, detail, approver), hashlib.sha256).hexdigest()


def verify(key: bytes, token: str | None, kind: str, avatar_id: str, subject: str, detail: str, approver: str) -> bool:
    if not token:
        return False
    expected = sign(key, kind, avatar_id, subject, detail, approver)
    return hmac.compare_digest(expected, token)


def new_key() -> bytes:
    return secrets.token_bytes(32)


def load_keyring(path: str) -> dict[str, bytes]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return {name: bytes.fromhex(hexkey) for name, hexkey in data.items()}


def save_keyring(path: str, keys: dict[str, bytes]) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({k: v.hex() for k, v in sorted(keys.items())}, fh, indent=2)
        fh.write("\n")
