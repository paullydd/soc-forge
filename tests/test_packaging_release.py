from __future__ import annotations

import json
import shutil
import subprocess
import sys
import venv
import zipfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_built_wheel_contains_rules_and_runs_outside_checkout(tmp_path):
    source_dir = tmp_path / "source"
    shutil.copytree(
        REPO_ROOT,
        source_dir,
        ignore=shutil.ignore_patterns(
            ".git",
            ".venv",
            "*.egg-info",
            "__pycache__",
            ".pytest_cache",
            "build",
            "dist",
            "out",
        ),
    )
    shutil.rmtree(source_dir / "soc_forge.egg-info", ignore_errors=True)

    wheel_dir = tmp_path / "wheel"
    wheel_dir.mkdir()
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--wheel-dir",
            str(wheel_dir),
            str(source_dir),
        ],
        check=True,
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )

    wheels = list(wheel_dir.glob("soc_forge-*.whl"))
    assert len(wheels) == 1
    wheel = wheels[0]
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()

    expected_rule_count = len(list((source_dir / "soc_forge" / "rules").glob("SOCF-*.yml")))
    rule_names = sorted(
        name for name in names if name.startswith("soc_forge/rules/SOCF-") and name.endswith(".yml")
    )
    assert len(rule_names) == expected_rule_count
    assert "soc_forge/rules/SOCF-021.yml" in rule_names
    assert "soc_forge/web/static/index.html" in names
    assert not any(name.startswith("tests/") or "/fixtures/" in name for name in names)

    environment = tmp_path / "venv"
    venv.EnvBuilder(with_pip=True, system_site_packages=True).create(environment)
    python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    subprocess.run(
        [str(python), "-m", "pip", "install", "--no-deps", str(wheel)],
        check=True,
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )

    run_dir = tmp_path / "outside-checkout"
    run_dir.mkdir()
    command = """
import json
from soc_forge.rules import BUILTIN_RULES_PATH
from soc_forge.rules.engine import load_rules, run_rules

rules = load_rules([str(BUILTIN_RULES_PATH)])
event = {
    "timestamp": "2026-07-29T12:00:00Z",
    "event_id": 4688,
    "host": "WIN-ENDPOINT-01",
    "username": "analyst",
    "process_name": "powershell.exe",
    "command_line": "powershell.exe Add-MpPreference -ExclusionPath C:\\\\Temp",
    "message": "Defender exclusion added",
}
alerts = run_rules([event], rules)
print(json.dumps({"rule_count": len(rules), "rule_ids": [a["rule_id"] for a in alerts]}))
"""
    completed = subprocess.run(
        [str(python), "-I", "-c", command],
        check=True,
        cwd=run_dir,
        capture_output=True,
        text=True,
    )
    result = json.loads(completed.stdout)
    assert result["rule_count"] == expected_rule_count
    assert "SOCF-021" in result["rule_ids"]
