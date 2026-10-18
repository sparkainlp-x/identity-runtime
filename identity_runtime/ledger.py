"""Append-only, hash-chained JSONL audit ledger that fails closed.

Each line is one canonical-JSON event whose ``hash`` covers every other field,
including ``prev_hash``. Editing, reordering or deleting a line breaks the
chain. A torn or unparsable last line (for example after a crash or a
truncation) makes the ledger read as broken, and a broken ledger refuses new
appends until an operator investigates. Dropping whole lines from the end is
caught by comparing against the head recorded in the runtime state file.

Payloads are copied to plain JSON before hashing, so later changes to a
caller's objects cannot change what was recorded.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable

from .util import canonical_json, frozen_copy, sha256_hex

GENESIS = "0" * 64


class LedgerIntegrityError(RuntimeError):
    pass


def _entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return sha256_hex(canonical_json(body))


class HashChainLedger:
    def __init__(self, path: str | None = None, clock: Callable[[], int] | None = None):
        import time

        self.path = path
        self.clock = clock or time.time_ns
        self.entries: list[dict[str, Any]] = []
        self.broken: str | None = None
        if path and os.path.exists(path):
            result = self.verify_chain()
            if not result["valid"]:
                self.broken = result["reason"]

    # -- reading ---------------------------------------------------------
    def _read_lines(self) -> list[str] | str:
        if not self.path:
            return [canonical_json(e) for e in self.entries]
        with open(self.path, "rb") as fh:
            raw = fh.read()
        if not raw:
            return []
        if not raw.endswith(b"\n"):
            return "last line is truncated (no trailing newline)"
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return "ledger is not valid UTF-8"
        return text.splitlines()

    def verify_chain(self) -> dict[str, Any]:
        lines = self._read_lines()
        if isinstance(lines, str):
            return {"valid": False, "entries": None, "reason": lines}
        prev = GENESIS
        entries = []
        for i, line in enumerate(lines):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return {"valid": False, "entries": i, "reason": f"line {i + 1} is not valid JSON"}
            if not isinstance(entry, dict):
                return {"valid": False, "entries": i, "reason": f"line {i + 1} is not an object"}
            if entry.get("seq") != i:
                return {"valid": False, "entries": i, "reason": f"line {i + 1} has seq {entry.get('seq')!r}, expected {i}"}
            if entry.get("prev_hash") != prev:
                return {"valid": False, "entries": i, "reason": f"line {i + 1} prev_hash does not match"}
            if entry.get("hash") != _entry_hash(entry):
                return {"valid": False, "entries": i, "reason": f"line {i + 1} hash does not match its content"}
            prev = entry["hash"]
            entries.append(entry)
        self.entries = entries
        return {"valid": True, "entries": len(entries), "head": prev, "reason": None}

    def head(self) -> dict[str, Any]:
        if not self.entries:
            return {"seq": -1, "hash": GENESIS}
        return {"seq": self.entries[-1]["seq"], "hash": self.entries[-1]["hash"]}

    def check_head(self, expected: dict[str, Any] | None) -> None:
        """Fail closed if the ledger is shorter than, or diverges from, a recorded head."""
        if not expected or expected.get("seq", -1) < 0:
            return
        seq = expected["seq"]
        if seq >= len(self.entries) or self.entries[seq]["hash"] != expected["hash"]:
            self.broken = f"ledger does not contain the recorded head (seq {seq}); lines may have been removed"

    # -- writing ---------------------------------------------------------
    def append(self, event: str, identity_root: str | None, payload: dict[str, Any]) -> dict[str, Any]:
        if self.broken:
            raise LedgerIntegrityError(f"ledger is broken, refusing to append: {self.broken}")
        head = self.head()
        entry = {
            "seq": head["seq"] + 1,
            "ts_ns": int(self.clock()),
            "event": event,
            "identity_root": identity_root,
            "payload": frozen_copy(payload),
            "prev_hash": head["hash"],
        }
        entry["hash"] = _entry_hash(entry)
        if self.path:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(canonical_json(entry) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        self.entries.append(entry)
        return frozen_copy(entry)

    def find(self, event: str | None = None, **payload_match: Any) -> list[dict[str, Any]]:
        out = []
        for e in self.entries:
            if event and e["event"] != event:
                continue
            if all(e["payload"].get(k) == v for k, v in payload_match.items()):
                out.append(frozen_copy(e))
        return out
