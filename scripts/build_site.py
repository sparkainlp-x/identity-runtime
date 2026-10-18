"""Build the static GitHub Pages site: run the demo and render it as plain HTML.

Usage: python scripts/build_site.py _site
index.html has no JavaScript; animation.html and talk.html use inline vanilla
JavaScript with data recorded or curated at build time. No backend and no external requests.
"""

from __future__ import annotations

import html
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from identity_runtime import __version__  # noqa: E402
from identity_runtime.demo import run_demo  # noqa: E402
from identity_runtime.story import record_story  # noqa: E402

TEMPLATE = ROOT / "site" / "animation.template.html"
PLACEHOLDER = "/*STORY_DATA*/"


def build_animation(out_dir: Path) -> Path:
    """Write animation.html with the recorded story embedded as inline JSON."""
    data = json.dumps(record_story(), ensure_ascii=False, separators=(",", ":"))
    data = data.replace("<", "\\u003c")  # "<" only occurs inside JSON strings
    template = TEMPLATE.read_text(encoding="utf-8")
    assert template.count(PLACEHOLDER) == 1
    target = out_dir / "animation.html"
    target.write_text(template.replace(PLACEHOLDER, data), encoding="utf-8")
    return target

TALK_TEMPLATE = ROOT / "site" / "talk.template.html"
TALK_QA = ROOT / "site" / "tesla_qa.json"
TALK_PLACEHOLDER = "/*TALK_DATA*/"
PORTRAIT = ROOT / "site" / "assets" / "tesla-sarony-c1890.jpg"
TALK_SAMPLES = ["who_are_you", "induction_motor", "wardenclyffe", "myth_free_energy", "myth_death_ray"]


def record_talk_session(personality: Path | None = None) -> dict:
    """Commit the Tesla-inspired personality in a scratch runtime and record what the talk page may do.

    The page is a read-only educational action: one respond_in_chat lease in the
    education context. send_email and spend_money are requested too, so the page
    can show the runtime's real refusal reasons rather than a hand-written claim.
    """
    from identity_runtime.runtime import IdentityRuntime

    manifest = json.loads(Path(personality or ROOT / "personalities" / "tesla.json").read_text(encoding="utf-8"))
    avatar = manifest["avatar_id"]
    with tempfile.TemporaryDirectory() as tmp:
        rt = IdentityRuntime(str(Path(tmp) / "state"))
        up = rt.receive_personality(manifest)
        mc = up["manifest_checksum"]
        for m in up["awaiting"]:
            rt.approve_module(avatar, mc, m, "alice")
        for m, n in up["awaiting"].items():
            if n == 2:
                rt.approve_module(avatar, mc, m, "bob")
        ident = rt.current_identity(avatar)
        assert ident["active"] == mc, "personality did not commit"
        rt.grant_lease(avatar, "respond_in_chat", "alice", max_actions=1, ttl_seconds=600)
        chat = rt.request_action(avatar, "respond_in_chat", "education", 0.1, "Answer a visitor's question from the scripted notes")
        mail = rt.request_action(avatar, "send_email", "education", 0.1, "Email a visitor")
        money = rt.request_action(avatar, "spend_money", "education", 0.1, "Buy something")
        verify = rt.verify()
    return {
        "version": __version__,
        "avatar_id": avatar,
        "manifest_version": manifest["manifest_version"],
        "manifest_checksum": mc,
        "identity_root": up["identity_root"],
        "quorum_modules": sorted(m for m, n in up["awaiting"].items() if n == 2),
        "actions": {
            "respond_in_chat": chat["decision"],
            "send_email": f"{mail['decision']} ({mail.get('reason', '')})",
            "spend_money": f"{money['decision']} ({money.get('reason', '')})",
        },
        "ledger": {"valid": verify["valid"], "entries": verify.get("entries")},
    }


def talk_data() -> dict:
    """Curated Q&A plus entries generated from personalities/tesla.json."""
    manifest = json.loads((ROOT / "personalities" / "tesla.json").read_text(encoding="utf-8"))
    mods = manifest["modules"]
    persona_src = {"title": "personalities/tesla.json", "url": "https://github.com/sparkainlp-x/identity-runtime/blob/main/personalities/tesla.json"}
    qa = json.loads(TALK_QA.read_text(encoding="utf-8"))
    generated = [
        {"id": "greeting", "topic": "about", "myth": False, "generated": True, "q": "Hello",
         "keywords": ["hello", "hi", "hey", "good morning", "good evening", "bonjour", "greetings"],
         "a": mods["interaction"]["greeting"], "source": persona_src},
        {"id": "myths_overview", "topic": "myths", "myth": True, "generated": True, "q": "Which Tesla myths do you correct?",
         "keywords": ["myths", "myth", "legends", "false", "misconceptions", "true or false", "fake"],
         "a": "Here are the myths my personality file asks me to correct. " + " ".join(mods["safety_policy"]["myths_to_correct"]),
         "source": persona_src},
    ]
    return {
        "persona": {
            "display_name": manifest["display_name"],
            "disclaimer": mods["identity"]["disclaimer"],
            "greeting": mods["interaction"]["greeting"],
            "handoff_phrase": mods["interaction"]["handoff_phrase"],
            "voice_label": mods["voice"]["synthetic_voice_label"],
            "voice_pace": mods["voice"]["pace"],
        },
        "entries": generated + qa["entries"],
        "session": record_talk_session(),
    }


def build_talk(out_dir: Path) -> Path:
    """Write talk.html with the scripted Q&A and recorded session embedded, and copy the portrait."""
    data = json.dumps(talk_data(), ensure_ascii=False, separators=(",", ":"))
    data = data.replace("<", "\\u003c")
    template = TALK_TEMPLATE.read_text(encoding="utf-8")
    assert template.count(TALK_PLACEHOLDER) == 1
    assets = out_dir / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(PORTRAIT, assets / PORTRAIT.name)
    entries = json.loads(TALK_QA.read_text(encoding="utf-8"))["entries"]
    by_id = {e["id"]: e for e in entries}

    def qa_html(items: list[dict]) -> str:
        rows = "".join(
            f'<dt>{html.escape(e["q"])}</dt><dd>{html.escape(e["a"])} '
            f'<span class="src">Source: <a href="{html.escape(e["source"]["url"])}">{html.escape(e["source"]["title"])}</a></span></dd>'
            for e in items
        )
        return f"<dl>{rows}</dl>"

    page = template.replace(TALK_PLACEHOLDER, data)
    page = page.replace("<!--SAMPLE_QA-->", qa_html([by_id[i] for i in TALK_SAMPLES]), 1)
    page = page.replace("<!--NOSCRIPT_QA-->", qa_html(entries), 1)
    target = out_dir / "talk.html"
    target.write_text(page, encoding="utf-8")
    return target


CSS = """
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;line-height:1.5;color:#1d1d1f;background:#fff}
h1{font-size:1.6rem}h2{font-size:1.25rem;margin-top:2rem}
.note{border-left:4px solid #6b5bd2;background:#f4f2ff;padding:.6rem 1rem}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:.35rem .5rem;text-align:left;vertical-align:top}
th{background:#f3f3f3}code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.85rem}
pre{background:#f6f6f6;padding:.75rem;overflow-x:auto;max-height:28rem}
details{margin:.4rem 0}a{color:#3b2fa8}
@media (prefers-color-scheme:dark){body{background:#151517;color:#e8e8ea}.note{background:#24203a}th{background:#222}pre{background:#1e1e21}td,th{border-color:#444}a{color:#b3a8ff}}
"""


def outcome(result) -> str:
    if isinstance(result, list):
        return f"{len(result)} leases granted"
    for key in ("decision", "status"):
        if key in result:
            extra = result.get("reason") or ", ".join(result.get("reasons", [])) or ""
            return f"{result[key]}" + (f" ({extra})" if extra else "")
    if "valid" in result:
        return f"ledger valid: {result['valid']}, {result.get('entries')} entries"
    return ""


def build(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        steps = run_demo(tmp)
    rows = "\n".join(
        f"<tr><td>{s['step']}</td><td>{html.escape(s['title'])}</td><td><code>{html.escape(outcome(s['result']))}</code></td></tr>"
        for s in steps
    )
    details = "\n".join(
        f"<details><summary>Step {s['step']}: {html.escape(s['title'])}</summary><pre>{html.escape(json.dumps(s['result'], indent=2, ensure_ascii=False))}</pre></details>"
        for s in steps
    )
    personas = ""
    for name in ("tesla.json", "sparky.json"):
        text = (ROOT / "personalities" / name).read_text(encoding="utf-8")
        personas += f"<details><summary>personalities/{name}</summary><pre>{html.escape(text)}</pre></details>\n"
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>identity-runtime: lifecycle demo</title><style>{CSS}</style></head>
<body>
<h1>identity-runtime: lifecycle demo</h1>
<p class="note">Research prototype. Classical, deterministic, standard-library Python. This page shows the output of
<code>python -m identity_runtime demo</code> (version {html.escape(__version__)}), recorded when the page was built. Nothing runs in your browser and no data is sent anywhere.</p>
<p>The demo uploads a fictional educational character inspired by the historical inventor Nikola Tesla (1856-1943). It is not Nikola Tesla and is not affiliated with Tesla, Inc. The upload is checked against the schema and simulated, waits for human approvals (two distinct people for tool and safety policy), commits, then requests actions under human-granted leases.</p>
<p><a href="animation.html">Animated walkthrough of the same lifecycle</a> (keyboard controls, captions, respects reduced-motion settings).</p>
<p><a href="talk.html">Talk with the Tesla guide</a>: ask the same character questions by typing or speaking and hear scripted, sourced answers in a browser voice. A fictional character, not Tesla himself and not an AI chatbot.</p>
<h2>Steps</h2>
<table><thead><tr><th>#</th><th>Step</th><th>Outcome</th></tr></thead><tbody>
{rows}
</tbody></table>
<h2>Full output</h2>
{details}
<h2>Example personalities</h2>
{personas}
<h2>Limits</h2>
<ul>
<li>Text screening catches copy-pasted attacks, not paraphrases.</li>
<li>The OES-61440 tripwire is a fixed, uncalibrated threshold hierarchy, not a learned model and not a safety guarantee.</li>
<li>The runtime authorises and records; it executes nothing and provides no sandbox.</li>
<li>Approval tokens are optional shared-secret HMACs, not public-key signatures. The ledger is tamper-evident, not tamper-proof.</li>
</ul>
<p>Source, tests and citation: <a href="https://github.com/sparkainlp-x/identity-runtime">github.com/sparkainlp-x/identity-runtime</a>. AGPL-3.0-only. Author: Jean-François Brisson, Spark AI NLP, Fredericton, New Brunswick, Canada.</p>
</body></html>
"""
    target = out_dir / "index.html"
    target.write_text(page, encoding="utf-8")
    (out_dir / ".nojekyll").write_text("", encoding="utf-8")
    build_animation(out_dir)
    build_talk(out_dir)
    return target


if __name__ == "__main__":
    print(build(Path(sys.argv[1] if len(sys.argv) > 1 else "_site")))
