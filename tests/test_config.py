from pathlib import Path

from soc_forge.config import load_config


def test_load_config_defaults_when_missing(tmp_path: Path):
    cfg = load_config(str(tmp_path / "nope.yml"))
    assert cfg.output.alerts_json == "out/alerts.json"
    assert cfg.bruteforce.threshold == 8


def test_load_config_reads_values(tmp_path: Path):
    p = tmp_path / "config.yml"
    p.write_text(
        """
output:
  alerts_json: "out/a.json"
  report_html: "out/r.html"
detections:
  brute_force:
    threshold: 12
    window_minutes: 5
    severity: "high"
    score: 77
correlation:
  window_minutes: 9
""",
        encoding="utf-8",
    )

    cfg = load_config(str(p))
    assert cfg.output.alerts_json == "out/a.json"
    assert cfg.output.report_html == "out/r.html"
    assert cfg.bruteforce.threshold == 12
    assert cfg.bruteforce.window_minutes == 5
    assert cfg.bruteforce.score == 77
    assert cfg.correlation.window_minutes == 9
