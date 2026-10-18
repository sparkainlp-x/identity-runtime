import subprocess
import sys

from conftest import ROOT


def test_site_builds_without_script_tags(tmp_path):
    subprocess.run([sys.executable, str(ROOT / "scripts" / "build_site.py"), str(tmp_path)], check=True, capture_output=True)
    page = (tmp_path / "index.html").read_text(encoding="utf-8")
    assert "<script" not in page.lower()
    assert "held_for_human" in page and "authorised_autonomously" in page
    assert "not affiliated with Tesla, Inc." in page


def test_animation_embeds_recorded_story_and_is_self_contained(tmp_path):
    import json
    import re

    subprocess.run([sys.executable, str(ROOT / "scripts" / "build_site.py"), str(tmp_path)], check=True, capture_output=True)
    page = (tmp_path / "animation.html").read_text(encoding="utf-8")
    assert "/*STORY_DATA*/" not in page
    raw = re.search(r'<script id="story" type="application/json">(.*?)</script>', page, re.S).group(1)
    story = json.loads(raw)
    assert story["avatar_id"] == "tesla-edu-guide" and story["verify"]["valid"]
    assert story["identity_root"] in page
    # no external scripts, styles, fonts or images
    assert not re.search(r'<(script|link|img|iframe)[^>]+(src|href)="https?:', page)
    assert "@import" not in page and "url(http" not in page
    assert "prefers-reduced-motion" in page and "ArrowRight" in page and 'aria-live="polite"' in page
    assert "not affiliated with or endorsed by Tesla, Inc." in page
    assert 'href="animation.html"' in (tmp_path / "index.html").read_text(encoding="utf-8")
    assert 'href="talk.html"' in (tmp_path / "index.html").read_text(encoding="utf-8")
