import copy
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


class FakeClock:
    def __init__(self, start=1_800_000_000_000_000_000):
        self.now = start

    def __call__(self):
        self.now += 1_000  # strictly increasing
        return self.now

    def advance(self, seconds):
        self.now += int(seconds * 1_000_000_000)


def _load(rel):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


@pytest.fixture
def tesla():
    return copy.deepcopy(_load("personalities/tesla.json"))


@pytest.fixture
def sparky():
    return copy.deepcopy(_load("personalities/sparky.json"))


@pytest.fixture
def malicious():
    return copy.deepcopy(_load("examples/malicious.json"))


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def make_runtime(tmp_path, clock):
    from identity_runtime import IdentityRuntime

    def factory(**kw):
        return IdentityRuntime(str(tmp_path / "state"), clock=clock, **kw)

    return factory


def commit(rt, manifest, first="alice", second="bob"):
    up = rt.receive_personality(manifest)
    assert up["status"] == "pending_approval", up
    mc = up["manifest_checksum"]
    last = None
    for module in list(up["awaiting"]):
        last = rt.approve_module(manifest["avatar_id"], mc, module, first)
    for module, n in up["awaiting"].items():
        if n == 2:
            last = rt.approve_module(manifest["avatar_id"], mc, module, second)
    assert last["status"] == "committed", last
    return mc
