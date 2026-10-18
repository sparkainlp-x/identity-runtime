import json
import re
import subprocess
import sys

import pytest

from conftest import ROOT

QA = ROOT / "site" / "tesla_qa.json"
BANNED_WORDS = ["proven", "validated", "production-ready", "production ready", "revolutionary", "quantum advantage", "real-world performance"]
# Statements that would assert a myth instead of correcting it.
MYTH_ASSERTIONS = [
    r"free energy (is|was) (real|possible)",
    r"(built|invented|made) a (working )?free[- ]energy",
    r"over-?unity (device|machine) (works|worked)",
    r"(built|demonstrated) a working death ray",
    r"invented electricity\.",
    r"delivered wireless power to (homes|houses|customers)",
    r"(heals|cures|healing effects? of)",
]
EMOJI = re.compile("[\U0001F000-\U0001FAFF\u2600-\u27BF\u2B00-\u2BFF\uFE0F]")


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    out = tmp_path_factory.mktemp("site")
    subprocess.run([sys.executable, str(ROOT / "scripts" / "build_site.py"), str(out)], check=True, capture_output=True)
    return out


def load_entries():
    return json.loads(QA.read_text(encoding="utf-8"))["entries"]


def test_qa_loads_and_every_entry_has_answer_and_source():
    entries = load_entries()
    assert 40 <= len(entries) <= 60
    ids = [e["id"] for e in entries]
    assert len(ids) == len(set(ids))
    for e in entries:
        assert e["q"].strip() and len(e["a"].strip()) > 40, e["id"]
        assert e["keywords"] and all(k.strip() for k in e["keywords"]), e["id"]
        assert isinstance(e["myth"], bool), e["id"]
        assert e["source"]["title"].strip(), e["id"]
        assert e["source"]["url"].startswith("https://"), e["id"]


def test_required_topics_are_covered():
    ids = {e["id"] for e in load_entries()}
    for needed in ["born", "induction_motor", "tesla_coil", "wardenclyffe", "edison_rivalry", "westinghouse", "radio_inventor",
                   "colorado", "later_years", "myth_free_energy", "myth_death_ray", "myth_electricity", "myth_369", "myth_wireless_homes"]:
        assert needed in ids, needed


def test_myth_entries_correct_rather_than_assert():
    entries = load_entries()
    myths = [e for e in entries if e["myth"]]
    assert len(myths) >= 8
    for e in entries:
        text = e["a"].lower()
        for pattern in MYTH_ASSERTIONS:
            assert not re.search(pattern, text), (e["id"], pattern)
    by_id = {e["id"]: e for e in entries}
    for key in ["myth_free_energy", "myth_death_ray", "myth_electricity", "myth_wireless_homes", "myth_radiant_patent", "nobel"]:
        assert by_id[key]["a"].startswith("No"), key
    assert "conservation of energy" in by_id["myth_free_energy"]["a"]


def test_no_banned_words_or_emoji_in_answers():
    raw = QA.read_text(encoding="utf-8")
    for word in BANNED_WORDS:
        assert not re.search(r"\b" + re.escape(word) + r"\b", raw, re.I), word
    assert not EMOJI.search(raw)


def test_talk_page_is_self_contained_and_labelled(site):
    page = (site / "talk.html").read_text(encoding="utf-8")
    assert "/*TALK_DATA*/" not in page
    # no external scripts, styles, fonts, images or frames
    assert not re.search(r'<(script|link|img|iframe|source|audio|video)[^>]+(src|href)="(https?:)?//', page)
    assert "@import" not in page and "url(" not in page
    assert '<img src="assets/tesla-sarony-c1890.jpg"' in page
    assert (site / "assets" / "tesla-sarony-c1890.jpg").read_bytes()[:3] == b"\xff\xd8\xff"
    # disclaimer at the top and in the footer
    header, footer = page.split("<main>")[0], page.split("<footer>")[1]
    for part in (header, footer):
        assert "Nikola Tesla (1856-1943)" in part
        assert "not an AI chatbot" in part
        assert "not affiliated with or endorsed by Tesla, Inc." in part.replace("Not affiliated", "not affiliated")
        assert "Tesla himself" in part
    # attribution for the photograph
    assert "Napoleon Sarony" in page and "c. 1890" in page and "Public domain" in page
    assert "https://commons.wikimedia.org/wiki/File:Tesla_circa_1890.jpeg" in page
    # speech, accessibility and motion
    for needle in ["SpeechRecognition", "webkitSpeechRecognition", "speechSynthesis", 'aria-live="polite"', "prefers-reduced-motion", "I don't have a scripted answer for that"]:
        assert needle in page, needle
    for word in BANNED_WORDS:
        assert not re.search(r"\b" + re.escape(word) + r"\b", page, re.I), word
    assert not EMOJI.search(page)


def test_talk_page_embeds_committed_persona_and_refused_actions(site):
    page = (site / "talk.html").read_text(encoding="utf-8")
    raw = re.search(r'<script id="talk" type="application/json">(.*?)</script>', page, re.S).group(1)
    data = json.loads(raw)
    s = data["session"]
    assert s["avatar_id"] == "tesla-edu-guide" and len(s["manifest_checksum"]) == 64
    assert s["actions"]["respond_in_chat"] == "authorised_autonomously"
    assert s["actions"]["send_email"].startswith("denied")
    assert s["actions"]["spend_money"].startswith("denied")
    assert s["ledger"]["valid"] is True
    assert data["persona"]["greeting"].startswith("Hello. I am the Inventor's Notebook guide")
    ids = [e["id"] for e in data["entries"]]
    assert "greeting" in ids and "myths_overview" in ids and len(ids) == len(set(ids))


def test_credits_file_records_image_source_and_status():
    text = (ROOT / "CREDITS.md").read_text(encoding="utf-8")
    for needle in ["Napoleon Sarony", "circa 1890", "public domain", "PD-old-100-expired", "https://commons.wikimedia.org/wiki/File:Tesla_circa_1890.jpeg"]:
        assert needle in text, needle
