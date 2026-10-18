"""Build the static GitHub Pages site: run the demo and render it as plain HTML.

Usage: python scripts/build_site.py _site
No JavaScript, no backend; the page shows output recorded at build time.
"""

from __future__ import annotations

import html
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from identity_runtime import __version__  # noqa: E402
from identity_runtime.demo import run_demo  # noqa: E402

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
    return target


if __name__ == "__main__":
    print(build(Path(sys.argv[1] if len(sys.argv) > 1 else "_site")))
