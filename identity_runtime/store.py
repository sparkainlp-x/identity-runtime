"""Persistent state: version store (by manifest checksum) and runtime state."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any

from .util import checksum, frozen_copy

STATE_FORMAT = 1


class StoreError(RuntimeError):
    pass


def _atomic_write(path: str, text: str) -> None:
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


class Store:
    """Files under ``root`` or, when root is None, plain dictionaries in memory."""

    def __init__(self, root: str | None):
        self.root = root
        self._versions: dict[str, dict[str, Any]] = {}
        self._state: dict[str, Any] = {"format": STATE_FORMAT, "ledger_head": None, "avatars": {}}
        if root:
            os.makedirs(os.path.join(root, "versions"), exist_ok=True)
            if os.path.exists(self.state_path):
                with open(self.state_path, encoding="utf-8") as fh:
                    self._state = json.load(fh)
                if self._state.get("format") != STATE_FORMAT:
                    raise StoreError(f"unsupported state format {self._state.get('format')!r}")

    @property
    def state_path(self) -> str:
        return os.path.join(self.root or "", "state.json")

    @property
    def ledger_path(self) -> str | None:
        return os.path.join(self.root, "ledger.jsonl") if self.root else None

    @property
    def state(self) -> dict[str, Any]:
        return self._state

    def save_state(self) -> None:
        if self.root:
            _atomic_write(self.state_path, json.dumps(self._state, indent=2, sort_keys=True) + "\n")

    def put_version(self, manifest_checksum: str, record: dict[str, Any]) -> None:
        record = frozen_copy(record)
        if checksum(record["manifest"]) != manifest_checksum:
            raise StoreError("manifest checksum mismatch on write")
        self._versions[manifest_checksum] = record
        if self.root:
            path = os.path.join(self.root, "versions", f"{manifest_checksum}.json")
            if not os.path.exists(path):
                _atomic_write(path, json.dumps(record, indent=2, sort_keys=True) + "\n")

    def get_version(self, manifest_checksum: str) -> dict[str, Any]:
        record = self._versions.get(manifest_checksum)
        if record is None and self.root:
            path = os.path.join(self.root, "versions", f"{manifest_checksum}.json")
            if not os.path.exists(path):
                raise StoreError(f"version {manifest_checksum[:12]} not found in the version store")
            with open(path, encoding="utf-8") as fh:
                record = json.load(fh)
        if record is None:
            raise StoreError(f"version {manifest_checksum[:12]} not found in the version store")
        if checksum(record["manifest"]) != manifest_checksum:
            raise StoreError(f"version {manifest_checksum[:12]} failed its checksum (tampered or corrupt)")
        return frozen_copy(record)
