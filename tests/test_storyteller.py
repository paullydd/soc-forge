from soc_forge.intelligence.storyteller import build_case_story


def test_build_case_story_includes_timeline_language():
    case = {
        "alerts": [
            {
                "rule_id": "SOCF-006",
                "timestamp": "2026-03-12T08:01:00",
                "username": "bob",
                "host": "WIN10",
                "src_ip": "10.0.0.5",
            },
            {
                "rule_id": "SOCF-005",
                "timestamp": "2026-03-12T08:05:00",
                "username": "bob",
                "host": "WIN10",
                "src_ip": "10.0.0.5",
            },
        ],
        "case_risk": {"level": "high", "score": 85},
    }

    hunts = [
        {
            "hunt_id": "HUNT-003",
            "title": "Multi-Host User Spread",
            "summary": "User bob touched 3 hosts within 10 minutes",
            "severity": "medium",
            "first_seen": "2026-03-12T08:10:00",
            "entities": {
                "username": "bob",
                "hosts": ["WIN10", "DC01", "FILE01"],
            },
        }
    ]

    story = build_case_story(case, hunts)

    assert "At 08:01" in story
    assert "At 08:05" in story
    assert "high" in story.lower()
    assert "bob" in story.lower()