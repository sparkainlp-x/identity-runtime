from identity_runtime.story import record_story


def test_story_records_the_real_lifecycle():
    s = record_story()
    assert s["avatar_id"] == "tesla-edu-guide"
    assert s["simulation"]["passed"] and len(s["simulation"]["probes"]) == 8
    assert set(s["auto_approved"]) == {"voice", "appearance"}
    bob = [a for a in s["approvals"] if a["approver"] == "bob"]
    assert {a["module"] for a in bob} == {"tool_policy", "safety_policy"} and bob[-1]["status"] == "committed"
    assert s["low_risk"]["decision"] == "authorised_autonomously" and not s["low_risk"]["fabric"]["checkpoint"]
    assert s["held"]["decision"] == "held_for_human" and "policy_requires_human" in s["held"]["reasons"]
    assert s["approved"]["approved_by"] == "bob"
    assert s["revoke"]["after"]["reason"] == "no_valid_lease"
    assert s["rollback"]["active"] == s["manifest_checksum"] and s["rollback"]["previous"] == s["v2"]["manifest_checksum"]
    assert s["malicious"]["status"] == "rejected"
    assert s["verify"]["valid"] and s["verify"]["entries"] == len(s["ledger"])
    assert s["tampered"]["verify"]["valid"] is False
    for a, b in zip(s["ledger"], s["ledger"][1:]):
        assert b["prev_hash"] == a["hash"]
    marks = list(s["marks"].values())
    assert marks == sorted(marks)
    assert len(s["held"]["fabric"]["membrane_counts"]) == 1920
