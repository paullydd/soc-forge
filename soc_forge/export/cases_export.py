import json
from pathlib import Path
from typing import Any, Dict, List


def export_cases_json(cases: List[Dict[str, Any]], output_dir: Path) -> None:
    """
    Write structured case data for external tools.
    """

    output_dir.mkdir(parents=True, exist_ok=True)

    out_file = output_dir / "cases.json"

    with open(out_file, "w") as f:
        json.dump(cases, f, indent=2)

    print(f"[soc-forge] Cases exported → {out_file}")
