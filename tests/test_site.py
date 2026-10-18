import subprocess
import sys

from conftest import ROOT


def test_site_builds_without_script_tags(tmp_path):
    subprocess.run([sys.executable, str(ROOT / "scripts" / "build_site.py"), str(tmp_path)], check=True, capture_output=True)
    page = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "<script" not in page.lower()
    assert "held_for_human" in page and "authorised_autonomously" in page
    assert "not affiliated with Tesla, Inc." in page
