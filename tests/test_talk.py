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
    assert 40 <= len(entries) <= 80
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
    for needle in ["SpeechRecognition", "webkitSpeechRecognition", "speechSynthesis", 'aria-live="polite"', "prefers-reduced-motion", "I only cover Nikola Tesla and the history of electricity"]:
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


def _js_block(start, end):
    page = TEMPLATE.read_text(encoding="utf-8")
    return page.split(start)[1].split(end)[0]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_voice_selection_prefers_male_and_lowers_pitch_otherwise():
    code = _js_block("/* ---- voice gender ---- */", "/* ---- end voice gender ---- */")
    lists = {
        "android_generic": [{"name": "English United Kingdom", "lang": "en-GB", "localService": True},
                            {"name": "English United States", "lang": "en-US", "localService": True, "default": True}],
        "android_ids": [{"name": "en-us-x-sfg-network", "lang": "en-US"}, {"name": "en-gb-x-gba-local", "lang": "en-GB"},
                        {"name": "en-gb-x-rjs-network", "lang": "en-GB"}, {"name": "en-us-x-tpf-local", "lang": "en-US"}],
        "android_us_ids": [{"name": "en-us-x-iob-local", "lang": "en_US"}, {"name": "en-us-x-iom-local", "lang": "en_US"}],
        "windows": [{"name": "Microsoft Zira Desktop - English (United States)", "lang": "en-US"},
                    {"name": "Microsoft Hazel Desktop - English (Great Britain)", "lang": "en-GB"},
                    {"name": "Microsoft David Desktop - English (United States)", "lang": "en-US"}],
        "edge_natural": [{"name": "Microsoft Aria Online (Natural) - English (United States)", "lang": "en-US"},
                         {"name": "Microsoft Sonia Online (Natural) - English (United Kingdom)", "lang": "en-GB"},
                         {"name": "Microsoft Ryan Online (Natural) - English (United Kingdom)", "lang": "en-GB"},
                         {"name": "Microsoft Guy Online (Natural) - English (United States)", "lang": "en-US"}],
        "macos": [{"name": "Samantha", "lang": "en-US", "default": True}, {"name": "Karen", "lang": "en-AU"},
                  {"name": "Moira", "lang": "en-IE"}, {"name": "Daniel", "lang": "en-GB"}, {"name": "Alex", "lang": "en-US"}],
        "chrome_desktop": [{"name": "Google US English", "lang": "en-US"}, {"name": "Google UK English Female", "lang": "en-GB"},
                           {"name": "Google UK English Male", "lang": "en-GB"}, {"name": "Google Deutsch", "lang": "de-DE"}],
        "only_female": [{"name": "Samantha", "lang": "en-US"}, {"name": "Google UK English Female", "lang": "en-GB"}],
        "empty": [],
    }
    script = code + (
        "const L=" + json.dumps(lists) + ";const out={};"
        "for(const k in L){const r=pickVoice(L[k]);out[k]={name:r.voice&&r.voice.name,gender:r.gender,pitch:r.pitch,lowered:r.lowered,"
        "order:r.ordered.map(v=>voiceGender(v))};}"
        "const s1=pickVoice(L.chrome_desktop,'Google UK English Female');out.saved_female={name:s1.voice.name,clear:s1.clearSaved};"
        "const s2=pickVoice(L.android_generic,'English United States');out.saved_unknown={name:s2.voice.name,clear:s2.clearSaved};"
        "out.variants=['en-gb-x-rjs#female_1-local','en-gb-x-fis#male_1-local','en-us-x-tpd-network','en-us-x-iol-local','en-gb-x-gbd-local'].map(n=>voiceGender({name:n}));"
        "console.log(JSON.stringify(out));"
    )
    out = json.loads(subprocess.run(["node", "-e", script], check=True, capture_output=True, text=True).stdout)
    assert out["android_ids"]["name"] == "en-gb-x-rjs-network" and out["android_ids"]["gender"] == "male"
    assert out["android_us_ids"]["name"] == "en-us-x-iom-local"
    assert out["windows"]["name"].startswith("Microsoft David")
    assert out["edge_natural"]["name"].startswith("Microsoft Ryan")  # male, and en-GB preferred
    assert out["macos"]["name"] == "Daniel"
    assert out["chrome_desktop"]["name"] == "Google UK English Male"
    for k in ["android_ids", "android_us_ids", "windows", "edge_natural", "macos", "chrome_desktop"]:
        assert out[k]["gender"] == "male" and out[k]["pitch"] == 0.75 and out[k]["lowered"] is False, k
        order = out[k]["order"]
        assert order == sorted(order, key=["male", "unknown", "female"].index), k  # male voices listed first
    # no voice known to be male: best non-female voice, lowered pitch
    assert out["android_generic"]["name"] == "English United Kingdom"
    assert out["android_generic"]["gender"] == "unknown" and out["android_generic"]["lowered"] and out["android_generic"]["pitch"] == 0.6
    assert out["only_female"]["lowered"] and out["only_female"]["pitch"] == 0.6
    assert out["empty"]["name"] is None and out["empty"]["pitch"] == 0.6
    # a saved female choice is dropped; a saved unknown choice is kept
    assert out["saved_female"] == {"name": "Google UK English Male", "clear": True}
    assert out["saved_unknown"] == {"name": "English United States", "clear": False}
    assert out["variants"] == ["female", "male", "male", "male", "male"]


def test_voice_controls_and_note_present(site):
    page = (site / "talk.html").read_text(encoding="utf-8")
    assert 'id="testVoice"' in page and ">Test voice<" in page
    assert 'id="voiceNote"' in page and "No voice on this device is known to be male, so the guide uses a lowered pitch." in page
    assert "voiceschanged" in page and "pointerdown" in page


def test_ai_portrait_is_labelled_still_and_never_animated(site):
    page = (site / "talk.html").read_text(encoding="utf-8")
    assert (site / "assets" / "tesla-ai-portrait-512.jpg").stat().st_size < 80_000
    img = re.search(r'<img id="aiPortrait"[^>]*>', page).group(0)
    assert 'src="assets/tesla-ai-portrait-512.jpg"' in img and "AI-generated" in img
    assert "class=" not in img and "style=" not in img
    assert "AI-generated portrait in the likeness of Nikola Tesla, supplied by the project author. Not a photograph. Not animated." in page
    script = page.split("<script>")[1]
    assert "aiPortrait" not in script  # JavaScript never touches the portrait image
    style = re.search(r"<style>(.*?)</style>", page, re.S).group(1)
    for rule in re.findall(r"([^{}]+)\{([^{}]*)\}", style):
        sel, body = rule
        if "aiPortrait" in sel or ".pframe img" in sel:
            assert not re.search(r"transform|animation|filter|mix-blend|clip-path|mask", body), sel
    # the glow sits behind the image (lower z-index) so nothing is drawn over the face
    assert re.search(r"\.pglow\{[^}]*z-index:0", style) and re.search(r"\.pframe img\{[^}]*z-index:1", style)
    for word in ["lip", "mouth", "viseme", "morph", "warp", "face"]:
        assert word not in img.lower().replace("likeness", ""), word
    assert b"trainedAlgorithmicMedia" in (ROOT / "site" / "assets" / "tesla-ai-portrait-512.jpg").read_bytes()


def _luminance(hex_colour):
    h = hex_colour.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    rgb = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    lin = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def test_avatar_skin_is_fair_solid_and_not_darkened(site):
    page = (site / "talk.html").read_text(encoding="utf-8")
    svg = re.search(r'<svg id="avatar".*?</svg>', page, re.S).group(0)
    face = re.search(r'<path id="face"[^>]*fill="([^"]+)"', svg).group(1)
    skins = [face] + re.findall(r'<ellipse class="skin"[^>]*fill="([^"]+)"', svg)
    skins += re.findall(r'<g id="lid[LR]"><rect[^>]*fill="([^"]+)"', svg)
    skins += re.findall(r'<g id="neck">(.*?)</g>', svg, re.S)[0] and re.findall(r'fill="(#[0-9a-fA-F]{3,6})"', re.search(r'<g id="neck">(.*?)</g>', svg, re.S).group(1))
    skins += re.findall(r'<ellipse cx="(?:110|210)" cy="152"[^>]*fill="([^"]+)"', svg)
    assert len(skins) >= 8
    for colour in skins:
        # solid colours only: Chrome's forced dark mode inverts light SVG gradients
        assert colour.startswith("#"), colour
        assert _luminance(colour) > 0.45, colour
    assert _luminance(face) > 0.45 and max(_luminance(c) for c in skins) > 0.75
    assert "filter=" not in svg and "mix-blend" not in svg and "<image" not in svg
    assert '<meta name="color-scheme" content="dark light">' in page and "forced-color-adjust:none" in page


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_matching_never_dead_ends_on_topical_questions(site):
    page = (site / "talk.html").read_text(encoding="utf-8")
    data = page.split('<script id="talk" type="application/json">')[1].split("</script>")[0]
    code = page.split("/* ---- matching ---- */")[1].split("/* ---- end matching ---- */")[0]
    queries = ["tell me about electricity", "electricity", "what is electricity", "how does electricity work",
               "what did he invent", "tell me about his life", "magnets", "power grid",
               "did tesla invent electricity", "what is the weather", "football scores", "electrisitty", "electrisity", "tesla"]
    script = (
        "const D=" + data + ";" + code +
        "console.log(JSON.stringify(" + json.dumps(queries) + ".map(function(q){var p=pick(q);"
        "return {kind:p.kind,id:p.entry&&p.entry.id,text:p.text,more:p.more.map(function(e){return e.id;})};})));"
    )
    out = json.loads(subprocess.run(["node", "-e", script], check=True, capture_output=True, text=True).stdout)
    got = dict(zip(queries, out))
    expected = {
        "tell me about electricity": "what_is_electricity", "electricity": "what_is_electricity",
        "what is electricity": "what_is_electricity", "how does electricity work": "electric_current",
        "what did he invent": "inventions_overview", "tell me about his life": "who_was_tesla",
        "magnets": "electromagnetism", "power grid": "power_grid_today",
        "did tesla invent electricity": "myth_electricity",
    }
    for q, want in expected.items():
        assert got[q]["kind"] == "answer" and got[q]["id"] == want, (q, got[q])
        assert len(got[q]["more"]) == 3, q
    for q in ["what is the weather", "football scores"]:
        assert got[q]["kind"] == "offtopic" and got[q]["id"] is None, (q, got[q])
        assert got[q]["text"].startswith("I only cover Nikola Tesla and the history of electricity"), q
        assert got[q]["more"], q
    # one slip in a long word answers outright; two slips get the closest note with a lead-in
    assert got["electrisity"]["kind"] == "answer" and got["electrisity"]["id"] == "what_is_electricity"
    assert got["electrisitty"]["kind"] == "closest" and got["electrisitty"]["id"] == "what_is_electricity"
    assert got["electrisitty"]["text"].startswith("Here is the closest note I have:")
    assert got["tesla"]["kind"] == "overview" and got["tesla"]["id"] == "who_was_tesla" and len(got["tesla"]["more"]) == 3


def _pick_in_node(site, queries, extra=""):
    """Run the page's matching block in node and return pick() for each query (plus anything extra prints)."""
    page = (site / "talk.html").read_text(encoding="utf-8")
    data = page.split('<script id="talk" type="application/json">')[1].split("</script>")[0]
    code = page.split("/* ---- matching ---- */")[1].split("/* ---- end matching ---- */")[0]
    script = (
        "const D=" + data + ";" + code +
        "const out={picks:" + json.dumps(queries) + ".map(function(q){var p=pick(q);"
        "return {kind:p.kind,id:p.entry&&p.entry.id,text:p.text,html:p.highlightedText,more:p.more.map(function(e){return e.id;})};})};"
        + extra + "console.log(JSON.stringify(out));"
    )
    out = json.loads(subprocess.run(["node", "-e", script], check=True, capture_output=True, text=True).stdout)
    out["picks"] = dict(zip(queries, out["picks"]))
    return out


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_synonyms_expand_in_questions_and_keywords(site):
    queries = ["ac motor", "what is DC?", "what is AC?", "AC/DC", "ac vs dc", "alternating current", "alternating current motor",
               "wardenclyffe", "wardenclyffe tower", "What was Wardenclyffe Tower?", "Wardenclyffe today", "wardencliff",
               "tell me about his lab", "lab fire", "laboratory fire", "light bulb", "bulbs", "edison dc", "dc motor",
               "tell me about electricity", "", "   ", "?!", "the", "what is the weather", "back in the day"]
    out = _pick_in_node(site, queries, "out.exp=['AC motor','ac/dc','Labs','bulb','back','lacquer','Wardenclyffe'].map(function(q){return expandSynonyms(q);});")
    got = out["picks"]
    expected = {
        "ac motor": "induction_motor", "alternating current motor": "induction_motor",
        "what is DC?": "ac_vs_dc", "what is AC?": "ac_vs_dc", "AC/DC": "ac_vs_dc", "alternating current": "ac_vs_dc",
        "ac vs dc": "war_of_currents",  # the literal phrase still outweighs "ac" plus "dc"
        "wardenclyffe": "wardenclyffe", "wardenclyffe tower": "wardenclyffe", "What was Wardenclyffe Tower?": "wardenclyffe",
        "Wardenclyffe today": "museum", "lab fire": "lab_fire", "laboratory fire": "lab_fire",
        "light bulb": "wireless_lighting", "bulbs": "wireless_lighting", "edison dc": "edison_rivalry", "dc motor": "how_motor_works",
        "tell me about electricity": "what_is_electricity",
        "tell me about his lab": "colorado",  # the Colorado Springs laboratory note; before synonyms this fell back to the overview
    }
    for q, want in expected.items():
        assert got[q]["kind"] == "answer" and got[q]["id"] == want, (q, got[q])
    assert got["wardencliff"]["kind"] == "closest" and got["wardencliff"]["id"] == "wardenclyffe"  # typo matching survives expansion
    for q in ["", "   ", "?!", "the", "what is the weather", "back in the day"]:
        assert got[q]["kind"] == "offtopic" and got[q]["id"] is None, (q, got[q])
    assert out["exp"] == ["alternating current motor", "alternating current/direct current", "laboratory", "lamp", "back", "lacquer", "tower laboratory"]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_every_keyword_still_reaches_its_note(site):
    # each keyword asked on its own must still lead to its note (as the answer, or tied at the top score)
    page = (site / "talk.html").read_text(encoding="utf-8")
    data = page.split('<script id="talk" type="application/json">')[1].split("</script>")[0]
    code = page.split("/* ---- matching ---- */")[1].split("/* ---- end matching ---- */")[0]
    script = (
        "const D=" + data + ";" + code +
        "var bad=[];D.entries.forEach(function(e){e.keywords.forEach(function(k){var r=score(k);"
        "var me=r.filter(function(z){return z.x.e.id===e.id;})[0];if(!me||me.s<r[0].s||me.s<1.5)bad.push([e.id,k,me&&me.s,r[0]&&r[0].x.e.id]);});});"
        "console.log(JSON.stringify(bad));"
    )
    bad = json.loads(subprocess.run(["node", "-e", script], check=True, capture_output=True, text=True).stdout)
    # "motor" alone goes to the general how-motors-work note; that was already so before synonyms were added
    assert [b[:2] for b in bad] == [["induction_motor", "motor"]], bad


def _well_formed_marks(html):
    # only <mark> and </mark> tags, never nested, always closed
    tags = re.findall(r"<[^>]*>", html)
    assert all(t in ("<mark>", "</mark>") for t in tags), tags
    depth = 0
    for t in tags:
        depth += 1 if t == "<mark>" else -1
        assert depth in (0, 1), html
    assert depth == 0, html
    assert "<mark></mark>" not in html


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_highlighted_text_is_escaped_and_well_formed(site):
    import html as _html
    attack = "<script>alert(1)</script>"
    queries = ["tell me about electricity", "ac motor", "wardenclyffe", "mark", attack, "", "electrisitty", "tesla", "amp quot"]
    extra = (
        "out.direct=[highlightMatches(" + json.dumps(attack) + "," + json.dumps(attack) + "),"
        "highlightMatches('<mark>Mark</mark> marks & \"quotes\" 5 amps','mark amp quot'),"
        "highlightMatches(" + json.dumps("Tesla's current, alternating current and currents in one direction") + ",'alternating direct current'),"
        "highlightMatches('x <b onclick=1>y</b>','')];"
    )
    out = _pick_in_node(site, queries, extra)
    got = out["picks"]
    for q, p in got.items():
        assert isinstance(p["html"], str) and p["html"], q
        _well_formed_marks(p["html"])
        # removing the marks and unescaping gives back exactly the plain text that is spoken
        assert _html.unescape(p["html"].replace("<mark>", "").replace("</mark>", "")) == p["text"], q
    assert "<mark>electricity</mark>" in got["tell me about electricity"]["html"].lower()
    assert "<mark>wardenclyffe</mark>" in got["wardenclyffe"]["html"].lower()
    assert "<mark>motor</mark>" in got["ac motor"]["html"].lower()
    assert "<script" not in got[attack]["html"] and got[attack]["kind"] == "offtopic"
    assert got[""]["kind"] == "offtopic" and "<mark>" not in got[""]["html"]
    assert got["electrisitty"]["kind"] == "closest" and got["tesla"]["kind"] == "overview"
    attack_html, mark_html, cur_html, empty_html = out["direct"]
    assert attack_html == "&lt;<mark>script</mark>&gt;<mark>alert</mark>(1)&lt;/<mark>script</mark>&gt;"
    _well_formed_marks(mark_html)
    assert mark_html == ("&lt;<mark>mark</mark>&gt;<mark>Mark</mark>&lt;/<mark>mark</mark>&gt; <mark>marks</mark> &amp; "
                         "&quot;<mark>quotes</mark>&quot; 5 <mark>amps</mark>")
    assert cur_html == "Tesla&#39;s <mark>current</mark>, <mark>alternating</mark> <mark>current</mark> and <mark>currents</mark> in one direction"
    assert empty_html == "x &lt;b onclick=1&gt;y&lt;/b&gt;"


def test_chat_bubble_renders_only_escaped_html_and_speaks_plain_text():
    page = TEMPLATE.read_text(encoding="utf-8")
    script = page.split("<script>")[1]
    # innerHTML is only ever cleared, or set from the html argument of add(), which ask() fills with pick().highlightedText
    sets = re.findall(r"(\w+(?:\.\w+)*)\.innerHTML\s*=\s*([^;]+);", script)
    assert sorted(v for _, v in sets) == ['""', '""', "html"], sets
    assert "insertAdjacentHTML" not in script and "outerHTML" not in script and "document.write" not in script
    assert "answer(p.entry,p.kind===\"offtopic\",p.text,p.highlightedText)" in script
    answer_fn = script.split("function answer(")[1].split("\nvar lastAnswer")[0]
    # speech, lip sync and captions get the plain text t; the marked-up html only reaches add()
    assert "speak(t,true)" in answer_fn and "lastAnswer=t;speak(t);" in answer_fn
    assert answer_fn.count("html") == 2  # the parameter and the add() argument
    assert not re.search(r"(speak|startSpeech|setCaption|chunkText|buildTimeline)\([^)]*(html|highlightedText)", script)
    style = re.search(r"<style>(.*?)</style>", page, re.S).group(1)
    assert re.search(r"\.msg p mark\{[^}]*background:#5a4a1c[^}]*color:#fff3cf", style)
    assert "@media (forced-colors:active){.msg p mark{background:Mark;color:MarkText" in style


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_every_listed_question_answers_with_its_own_note(site):
    # the question list, the topic map and the chips ask each note's question verbatim, so each must answer with that note
    page = (site / "talk.html").read_text(encoding="utf-8")
    entries = json.loads(page.split('<script id="talk" type="application/json">')[1].split("</script>")[0])["entries"]
    qs = [e["q"] for e in entries]
    got = _pick_in_node(site, qs)["picks"]
    wrong = [(e["q"], e["id"], got[e["q"]]["kind"], got[e["q"]]["id"]) for e in entries
             if got[e["q"]]["kind"] != "answer" or got[e["q"]]["id"] != e["id"]]
    assert wrong == [], wrong
    # the two that used to fail: numbers split by "and", and a phrase with words between its parts
    assert got["What about 3, 6 and 9?"]["id"] == "myth_369"
    assert got["What did Tesla do before coming to America?"]["id"] == "early_jobs"


# Natural phrasings: lower case, no punctuation, common typos and the English of a French speaker.
PARAPHRASES = [
    ("who invented the ac motor", "induction_motor"),
    ("how does an induction motor works", "how_motor_works"),
    ("tesla vs edison", "edison_rivalry"),
    ("did edison and tesla hate each other", "edison_rivalry"),
    ("what is the war of current", "war_of_currents"),
    ("difference between ac and dc", "ac_vs_dc"),
    ("where tesla was born", "born"),
    ("when he is born", "born"),
    ("tesla coil what is it", "tesla_coil"),
    ("how make a tesla coil at home", "build_coil"),
    ("is tesla invented the radio", "radio_inventor"),
    ("marconi or tesla for the radio", "radio_inventor"),
    ("what he did in colorado", "colorado"),
    ("wardencliffe tower", "wardenclyffe"),
    ("the tower of wardenclyffe what happened", "wardenclyffe"),
    ("free energy is real", "myth_free_energy"),
    ("death ray tesla", "myth_death_ray"),
    ("the numbers 3 6 9", "myth_369"),
    ("369 meaning", "myth_369"),
    ("was he married", "married"),
    ("how he died", "death"),
    ("did he won a nobel prize", "nobel"),
    ("tesla and pigeons", "pigeons"),
    ("how many patent he have", "patents"),
    ("what is electricty", "what_is_electricity"),
    ("what did tesla do before he came in america", "early_jobs"),
    ("tesla and westinghouse deal", "westinghouse"),
    ("niagara falls power plant", "niagara"),
    ("x-rays tesla", "xrays"),
    ("the boat with radio control", "radio_boat"),
    ("is tesla related to elon musk", "tesla_inc"),
    ("are you a robot", "are_you_ai"),
    ("explain me the electromagnetism", "electromagnetism"),
    ("who is nikola tesla", "who_was_tesla"),
    ("how electricity arrive to my house", "power_grid_today"),
    ("what is lightning", "lightning"),
    ("tesla frequencies heal", "myth_health"),
    ("the tesla unit in mri", "unit"),
    ("what he do in paris and budapest", "early_jobs"),
    ("when he arrive in new york", "arrival_us"),
    ("he was serbian or croatian", "nationality"),
    ("what university he go", "education"),
    ("did tesla make wireless electricity for homes", "myth_wireless_homes"),
    ("the earthquake machine", "myth_earthquake"),
    ("what is the difference between energy and power", "energy_vs_power")
]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_paraphrases_reach_the_right_note(site):
    assert len(PARAPHRASES) >= 30
    got = _pick_in_node(site, [q for q, _ in PARAPHRASES])["picks"]
    wrong = [(q, want, got[q]["kind"], got[q]["id"]) for q, want in PARAPHRASES if got[q]["kind"] != "answer" or got[q]["id"] != want]
    assert wrong == [], wrong


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_follow_up_chips_follow_the_conversation(site):
    convo = ["What is a Tesla coil?", "what was wardenclyffe", "did he receive signals from mars", "tell me about electricity",
             "free energy", "death ray", "3 6 9", "football scores", "edison"]
    extra = (
        "var asked={};out.convo=" + json.dumps(convo) + ".map(function(q){var p=pick(q,asked);"
        "var r={q:q,id:p.entry&&p.entry.id,kind:p.kind,more:p.more.map(function(e){return e.id;}),"
        "groups:p.more.map(function(e){return groupOf(e);}),group:groupOf(p.entry),before:Object.keys(asked),"
        "linked:p.more.map(function(e){return !!p.entry&&((p.entry.related||[]).indexOf(e.id)>=0||e.topic===p.entry.topic||groupOf(e)===groupOf(p.entry));})};"
        "if(p.entry)asked[p.entry.id]=1;return r;});"
        "out.groups=GROUPS.map(function(g){return [g.id,groupEntries(g.id).map(function(e){return e.id;})];});"
    )
    out = _pick_in_node(site, [], extra)
    for turn in out["convo"]:
        assert turn["more"], turn
        assert turn["id"] not in turn["more"], turn  # never the note just given
        assert "greeting" not in turn["more"], turn
        assert len(set(turn["more"])) == len(turn["more"]), turn
        assert not set(turn["more"]) & set(turn["before"]), turn  # nothing already answered while fresh notes remain
        if turn["kind"] == "answer":
            # chips are related notes, the same topic or the same group; broad notes only fill in once the group runs out
            assert turn["linked"][0] and turn["linked"] == sorted(turn["linked"], reverse=True), turn
    by_q = {t["q"]: t for t in out["convo"]}
    assert by_q["death ray"]["id"] == "myth_death_ray" and all(by_q["death ray"]["linked"])
    assert by_q["edison"]["id"] == "edison_rivalry" and by_q["edison"]["more"][0] == "war_of_currents"
    assert by_q["what was wardenclyffe"]["more"][0] == "myth_wireless_homes"
    # every note shown in the topic map belongs to exactly one group; the greeting is left out
    groups = dict((g, ids) for g, ids in out["groups"])
    assert list(groups) == ["life", "inventions", "basics", "wireless", "myths", "about"]
    flat = [i for ids in groups.values() for i in ids]
    entries = json.loads((site / "talk.html").read_text(encoding="utf-8").split('<script id="talk" type="application/json">')[1].split("</script>")[0])["entries"]
    assert sorted(flat) == sorted(e["id"] for e in entries if e["id"] != "greeting")
    assert all(len(ids) >= 4 for ids in groups.values()), {g: len(i) for g, i in groups.items()}
    assert "wardenclyffe" in groups["wireless"] and "ac_vs_dc" in groups["basics"] and "myth_369" in groups["myths"]


def test_related_notes_exist_and_are_not_self():
    entries = load_entries()
    ids = {e["id"] for e in entries}
    with_related = [e for e in entries if "related" in e]
    assert len(with_related) >= 12
    for e in with_related:
        assert e["related"] and len(set(e["related"])) == len(e["related"]), e["id"]
        assert all(r in ids and r != e["id"] for r in e["related"]), e["id"]


def test_topic_map_markup_and_script(site):
    page = (site / "talk.html").read_text(encoding="utf-8")
    assert '<section class="tmap" aria-labelledby="hMap">' in page and 'id="tgroups" role="group"' in page
    assert 'id="tpanel" role="region"' in page
    script = page.split("<script>")[1]
    for needle in ['setAttribute("aria-expanded"', 'setAttribute("aria-controls","tpanel")', "groupEntries(openGroup)", "(already answered)"]:
        assert needle in script, needle
    labels = re.findall(r'\{id:"(\w+)",label:"([^"]+)"', script)
    assert [l for _, l in labels] == ["Life", "Inventions", "Electricity basics", "Wireless & Wardenclyffe", "Myths & facts", "About this guide"]


def test_typewriter_reveal_follows_speech_and_is_instant_otherwise():
    script = TEMPLATE.read_text(encoding="utf-8").split("<script>")[1]
    answer_fn = script.split("function answer(")[1].split("\nvar lastAnswer")[0]
    # only when the answer will be spoken and motion is allowed
    assert 'if(!reduce&&synth&&!muted&&canAutoSpeak())typeInto(m.querySelector("p"),t);' in answer_fn
    cap = script.split("function setCaption(")[1].split("\n}")[0]
    assert "TY.reveal(reduce?text.length:n)" in cap  # driven by the same word timeline as the captions and lips
    fin = script.split("function finishSpeech(")[1].split("\n}")[0]
    assert "setCaption(TL.text,TL.text.length)" in fin  # stopping or finishing reveals the whole answer
    ty = script.split("function typeInto(")[1].split("\n}")[0]
    assert "createTreeWalker(p,NodeFilter.SHOW_TEXT)" in ty and "innerHTML" not in ty  # words wrapped as text nodes only
    style = TEMPLATE.read_text(encoding="utf-8").split("<style>")[1].split("</style>")[0]
    assert ".typing .w{opacity:0" in style and ".typing .w.on{opacity:1}" in style
