import json
from pathlib import Path
from typing import Any, Dict, List

from soc_forge.models import normalize_case


def export_cases_json(cases: List[Dict[str, Any]], output_dir: Path) -> None:
    """
    Write structured case data for external tools.
    """

    output_dir.mkdir(parents=True, exist_ok=True)

    out_file = output_dir / "cases.json"
    normalized_cases = [normalize_case(case, index) for index, case in enumerate(cases, start=1)]

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(normalized_cases, f, indent=2)

    print(f"[soc-forge] Cases exported → {out_file}")
