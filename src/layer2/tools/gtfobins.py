import json
from pathlib import Path


_CATALOG_PATH = Path(__file__).resolve().parents[3] / "data" / "gtfobins.json"
with _CATALOG_PATH.open(encoding="utf-8") as catalog_file:
    _CATALOG: dict[str, dict[str, object]] = json.load(catalog_file)


def check_gtfobins(binary: str) -> dict:
    """Check whether a binary is listed in the local GTFOBins catalog."""
    binary_name = Path(binary).name
    entry = _CATALOG.get(binary_name)
    if entry is None:
        return {"is_gtfobin": False, "functions": [], "risk": "none"}

    return {
        "is_gtfobin": True,
        "functions": entry["functions"],
        "risk": entry["risk"],
    }
