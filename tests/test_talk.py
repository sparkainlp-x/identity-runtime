import json
import re
import shutil
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
    assert "@import" not in page
    # only same-document references such as url(#gSkin) are allowed
    assert not re.search(r"url\(\s*['\"]?(?!#)", page)
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


TEMPLATE = ROOT / "site" / "talk.template.html"
REQUIRED_VISEMES = {"rest", "MBP", "A", "E", "O", "UW", "FV"}


def viseme_table():
    page = TEMPLATE.read_text(encoding="utf-8")
    raw = re.search(r'<script id="visemes" type="application/json">(.*?)</script>', page, re.S).group(1)
    return json.loads(raw)


def test_viseme_table_covers_letters_and_shapes():
    vis = viseme_table()
    shapes = vis["shapes"]
    assert REQUIRED_VISEMES <= set(shapes) and len(shapes) >= 6
    for name, p in shapes.items():
        assert set(p) == {"w", "open", "up", "round", "teeth"}, name
        assert all(isinstance(v, (int, float)) for v in p.values()), name
        assert 0 <= p["round"] <= 1 and 0 <= p["teeth"] <= 1 and 0 <= p["open"] <= 16 and 6 <= p["w"] <= 22, name
    letters = vis["letters"]
    assert set(letters) == set("abcdefghijklmnopqrstuvwxyz")
    assert all(v in shapes for v in letters.values())
    assert all(v in shapes for v in vis["digraphs"].values()) and all(v in shapes for v in vis["digit"])
    assert all(letters[c] == "MBP" for c in "bmp") and shapes["MBP"]["open"] == 0
    assert letters["f"] == letters["v"] == "FV"
    assert letters["o"] == "O" and letters["u"] == "UW" and letters["a"] == "A"
    for v in vis["vowels"]:
        assert shapes[v]["open"] >= 4, v
    assert shapes["O"]["round"] > shapes["E"]["round"] and shapes["A"]["open"] > shapes["E"]["open"]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_word_to_visemes_function_in_node():
    page = TEMPLATE.read_text(encoding="utf-8")
    code = page.split("/* ---- visemes ---- */")[1].split("/* ---- end visemes ---- */")[0]
    script = (
        "const VIS=" + json.dumps(viseme_table()) + ";" + code +
        "console.log(JSON.stringify(['bob','five','moon','the','Tesla','1888','who','shop','...','Ferraris,'].map(wordToVisemes)));"
    )
    out = subprocess.run(["node", "-e", script], check=True, capture_output=True, text=True).stdout
    bob, five, moon, the, tesla, year, who, shop, dots, ferraris = json.loads(out)
    assert bob == ["MBP", "O", "MBP"]
    assert five == ["FV", "E", "FV"]  # silent final e
    assert moon == ["MBP", "UW", "L"]
    assert the == ["L", "E"]
    assert tesla == ["L", "E", "CK", "L", "A"]
    assert year == ["E", "A", "E", "A", "E", "A", "E", "A"] and len(year) == 8
    assert who == ["UW", "O"]
    assert shop == ["SH", "O", "MBP"]
    assert dots == []
    assert ferraris[0] == "FV" and ferraris[-1] == "CK"


def test_avatar_svg_is_an_original_labelled_illustration(site):
    page = (site / "talk.html").read_text(encoding="utf-8")
    svg = re.search(r'<svg id="avatar".*?</svg>', page, re.S).group(0)
    for sid in ["mouth", "mouthInner", "mouthClip", "teeth", "lipLine", "stache", "browL", "browR", "eyeL", "eyeR", "lidL", "lidR", "head", "arcs", "coilGlow"]:
        assert f'id="{sid}"' in svg, sid
    assert "<image" not in svg and ".jpg" not in svg  # drawn shapes only, the photograph is not used
    assert "Illustrated character, not a likeness of a real photo" in page
    assert "Historical photo" in page and "Not animated and not the guide" in page
    assert 'role="img"' in svg and "<title" in svg and "<desc" in svg
    assert "onboundary" in page and "prefers-reduced-motion" in page
    assert "localStorage" in page and "keeps your voice, rate, pitch and mute choices in this browser" in page
    m = re.search(r'id="pitch"[^>]*value="([0-9.]+)"', page)
    assert 0.7 <= float(m.group(1)) <= 0.8
    assert re.search(r'id="rate"[^>]*value="0.9"', page)
    assert "google uk english male" in page.lower()


def test_static_text_and_noscript_fallback(site):
    page = (site / "talk.html").read_text(encoding="utf-8")
    assert "<!--SAMPLE_QA-->" not in page and "<!--NOSCRIPT_QA-->" not in page
    noscript = re.search(r"<noscript>(.*?)</noscript>", page, re.S).group(1)
    entries = load_entries()
    assert "JavaScript is off" in noscript
    import html as _html
    for e in entries:
        assert _html.escape(e["q"]) in noscript, e["id"]
    # visible text outside any script or noscript, readable by fetchers that run no JavaScript
    visible = re.sub(r"<(script|noscript|style)\b.*?</\1>", "", page, flags=re.S)
    by_id = {e["id"]: e for e in entries}
    for key in ["who_are_you", "induction_motor", "wardenclyffe", "myth_free_energy", "myth_death_ray"]:
        assert _html.escape(by_id[key]["a"]) in visible, key
    assert "not an AI chatbot" in visible and "send_email and spend_money are not available" in visible


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_fallback_timeline_is_ordered_and_covers_the_text():
    page = TEMPLATE.read_text(encoding="utf-8")
    script = (
        "const VIS=" + json.dumps(viseme_table()) + ";"
        "const js=" + json.dumps(page.split("<script>")[1]) + ";"
        "const grab=n=>{const i=js.indexOf('function '+n+'(');let d=0;for(let k=js.indexOf('{',i);k<js.length;k++){if(js[k]=='{')d++;if(js[k]=='}'&&!--d)return js.slice(i,k+1);}};"
        "eval(grab('wordToVisemes')+grab('buildTimeline')+grab('chunkText'));"
        "const t=" + json.dumps(json.loads(QA.read_text(encoding="utf-8"))["entries"][0]["a"] * 3) + ";"
        "const ch=chunkText(t),p=buildTimeline(ch[0].text,0.9);"
        "console.log(JSON.stringify({joined:ch.map(c=>c.text).join('')===t,maxlen:Math.max(...ch.map(c=>c.text.length)),"
        "ordered:p.segs.every((s,i)=>s.t1>s.t0&&(i==0||s.t0>=p.segs[i-1].t1-1e-6)),total:p.total,chars:ch[0].text.length}));"
    )
    out = json.loads(subprocess.run(["node", "-e", script], check=True, capture_output=True, text=True).stdout)
    assert out["joined"] and out["ordered"]
    assert out["maxlen"] <= 400
    rate = out["chars"] / (out["total"] / 1000)
    assert 8 <= rate <= 25  # characters per second at rate 0.9, in the range of typical browser voices
