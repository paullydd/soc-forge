from __future__ import annotations

import json
import shutil
import subprocess
import sys
import venv
import zipfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_child(command, *, cwd):
    completed = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    if completed.returncode:
        raise AssertionError(
            f"Child process failed with exit code {completed.returncode}: "
            f"{command!r}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


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
    _run_child(
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
        cwd=tmp_path,
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
    static_names = sorted(
        name for name in names if name.startswith("soc_forge/web/static/")
    )
    assert static_names == [
        "soc_forge/web/static/app.js",
        "soc_forge/web/static/index.html",
        "soc_forge/web/static/investigation_findings.js",
        "soc_forge/web/static/investigation_response_actions.js",
        "soc_forge/web/static/investigation_summary.js",
        "soc_forge/web/static/investigations.js",
        "soc_forge/web/static/operations_queue.js",
        "soc_forge/web/static/query_workbench.js",
        "soc_forge/web/static/styles.css",
    ]
    for module in (
        "soc_forge/investigations/workspace_service.py",
        "soc_forge/investigations/evidence_service.py",
        "soc_forge/investigations/reasoning_service.py",
        "soc_forge/investigations/timeline_query.py",
        "soc_forge/investigations/pivots.py",
        "soc_forge/investigations/handoff.py",
        "soc_forge/investigations/operations_prioritization.py",
        "soc_forge/investigations/operational_summary.py",
        "soc_forge/menus/architecture.py",
        "soc_forge/detection_engineering.py",
        "soc_forge/menus/detection_engineering.py",
    ):
        assert module in names
    metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
    with zipfile.ZipFile(wheel) as archive:
        metadata = archive.read(metadata_name).decode("utf-8")
    assert "Version: 3.0.0" in metadata
    assert "Requires-Dist: colorama<0.5,>=0.4.6" in metadata
    assert not any(
        name.startswith("tests/")
        or "/fixtures/" in name
        or "__pycache__" in name
        or name.endswith(".pyc")
        or name.startswith(("out/", "build/", "dist/"))
        for name in names
    )

    environment = tmp_path / "venv"
    venv.EnvBuilder(with_pip=True, system_site_packages=False).create(environment)
    python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    _run_child(
        [str(python), "-m", "pip", "install", str(wheel)],
        cwd=tmp_path,
    )

    run_dir = tmp_path / "outside-checkout"
    run_dir.mkdir()
    command = """
import json
from soc_forge import __version__
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
print(json.dumps({"version": __version__, "rule_count": len(rules), "rule_ids": [a["rule_id"] for a in alerts]}))
"""
    completed = _run_child(
        [str(python), "-I", "-c", command],
        cwd=run_dir,
    )
    result = json.loads(completed.stdout)
    assert result["version"] == "3.0.0"
    assert result["rule_count"] == expected_rule_count
    assert "SOCF-021" in result["rule_ids"]
