from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_local_security_exports_are_not_tracked_release_inputs():
    assert not (REPO_ROOT / "security_events.csv").exists()
    assert not (REPO_ROOT / "security_events.jsonl").exists()


def test_documentation_uses_repository_neutral_paths():
    for path in (REPO_ROOT / "docs").glob("*.md"):
        assert "/home/pauly/projects/soc-forge" not in path.read_text(encoding="utf-8")
