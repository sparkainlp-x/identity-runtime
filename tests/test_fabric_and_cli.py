import json
import subprocess
import sys

from conftest import ROOT
from identity_runtime import fabric
from identity_runtime.cli import main


def test_fabric_shape():
    assert fabric.TOTAL_CHANNELS == 61440
    assert (fabric.MEMBRANES, fabric.SUPERVISORS, fabric.SECTORS) == (1920, 480, 120)


def test_fabric_is_deterministic_and_monotone():
    a = fabric.evaluate(0.6, 0.5, 0, 0)
    assert a == fabric.evaluate(0.6, 0.5, 0, 0)
    counts = [fabric.evaluate(r, 0.3, 0, 0)["tripped_channels"] for r in (0.0, 0.3, 0.6, 0.9, 1.0)]
    assert counts == sorted(counts)


def test_fabric_levels():
    assert not fabric.evaluate(0.2, 0.1, 0, 0)["checkpoint"]
    hi = fabric.evaluate(0.7, 0.7, 0, 0)
    assert hi["checkpoint"] and not hi["halt"]
    assert fabric.evaluate(1.0, 0.8, 0, 1.0)["halt"]
    assert fabric.evaluate(float("nan"), 0.8, 0, 1.0)["halt"]


def run_cli(state, *args):
    return main(["--state", str(state), *args])


def test_cli_upload_flow(tmp_path, capsys):
    state = tmp_path / "st"
    tesla = str(ROOT / "personalities" / "tesla.json")
    assert run_cli(state, "upload", tesla) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "pending_approval"
    assert run_cli(state, "approve", "tesla-edu-guide", "all", "--as", "alice") == 0
    capsys.readouterr()
    assert run_cli(state, "approve", "tesla-edu-guide", "tool_policy", "safety_policy", "--as", "bob") == 0
    assert json.loads(capsys.readouterr().out)[-1]["status"] == "committed"
    assert run_cli(state, "grant", "tesla-edu-guide", "read_public_data", "--as", "alice", "--max-actions", "2") == 0
    capsys.readouterr()
    assert run_cli(state, "act", "tesla-edu-guide", "read_public_data", "--context", "research", "--risk", "0.2") == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "authorised_autonomously"
    assert run_cli(state, "grant", "tesla-edu-guide", "send_email", "--as", "alice") == 0
    capsys.readouterr()
    assert run_cli(state, "act", "tesla-edu-guide", "send_email", "--context", "approved_outreach") == 0
    held = json.loads(capsys.readouterr().out)
    assert held["decision"] == "held_for_human"
    assert run_cli(state, "approve-action", held["action_id"], "--as", "bob") == 0
    capsys.readouterr()
    assert run_cli(state, "revoke", "tesla-edu-guide", "send_email", "--reason", "done") == 0
    assert run_cli(state, "status", "tesla-edu-guide") == 0
    assert run_cli(state, "verify") == 0
    capsys.readouterr()
    assert run_cli(state, "upload", str(ROOT / "examples" / "malicious.json")) == 2
    assert run_cli(state, "rollback", "tesla-edu-guide", "--as", "carol") == 1  # nothing to roll back to


def test_cli_signed_flow(tmp_path, capsys):
    state, ring = tmp_path / "st", tmp_path / "ring.json"
    assert main(["keygen", str(ring), "alice", "bob"]) == 0
    base = ["--state", str(state), "--keyring", str(ring)]
    sparky = str(ROOT / "personalities" / "sparky.json")
    assert main([*base, "upload", sparky]) == 0
    assert main([*base, "approve", "sparky-the-beaver", "all", "--as", "alice"]) == 0
    assert main([*base, "approve", "sparky-the-beaver", "tool_policy", "safety_policy", "--as", "bob"]) == 0
    capsys.readouterr()
    assert main([*base, "approve", "sparky-the-beaver", "all", "--as", "mallory"]) != 0


def test_cli_validate(capsys):
    assert main(["validate", str(ROOT / "personalities" / "sparky.json")]) == 0
    assert main(["validate", str(ROOT / "examples" / "malicious.json")]) == 2


def test_module_entry_point_demo(tmp_path):
    proc = subprocess.run([sys.executable, "-m", "identity_runtime", "demo", "--state-dir", str(tmp_path / "d")], cwd=ROOT, capture_output=True, text=True, check=True)
    steps = json.loads(proc.stdout)
    decisions = [s["result"].get("decision") for s in steps if isinstance(s["result"], dict)]
    assert "authorised_autonomously" in decisions and "held_for_human" in decisions
    assert steps[-1]["result"]["valid"] is True


def test_no_runtime_dependencies():
    import ast
    import pathlib
    stdlib = set(sys.stdlib_module_names)
    for path in pathlib.Path(ROOT / "identity_runtime").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [node.module]
            else:
                continue
            for n in names:
                assert n.split(".")[0] in stdlib | {"__future__"}, (path.name, n)
