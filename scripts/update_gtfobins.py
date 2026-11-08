"""Download the official GTFOBins catalog and build the local JSON index."""

from __future__ import annotations

import io
import json
import tarfile
import urllib.request
from pathlib import Path

import yaml


REPOSITORY_URL = "https://github.com/GTFOBins/GTFOBins.github.io/archive/refs/heads/master.tar.gz"
OUTPUT_PATH = Path(__file__).resolve().parents[1] / "data" / "gtfobins.json"


def _risk(functions: list[str]) -> str:
    if any(function in functions for function in ("file-write", "command", "shell")):
        return "high"
    return "medium" if functions else "low"


def build_catalog(archive: bytes) -> dict[str, dict[str, object]]:
    """Parse GTFOBins Markdown front matter into the local catalog schema."""
    catalog: dict[str, dict[str, object]] = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for member in tar.getmembers():
            if "/_gtfobins/" not in member.name or member.isdir():
                continue
            file_obj = tar.extractfile(member)
            if file_obj is None:
                continue
            text = file_obj.read().decode("utf-8")
            if not text.startswith("---"):
                continue
            front_matter = text[3:]
            metadata = yaml.safe_load(front_matter) or {}
            raw_functions = metadata.get("functions", {})
            functions = sorted({str(item) for item in raw_functions})
            name = Path(member.name).name
            catalog[name] = {"functions": functions, "risk": _risk(functions)}
    return dict(sorted(catalog.items()))


def main() -> None:
    """Fetch and write the complete GTFOBins catalog."""
    with urllib.request.urlopen(REPOSITORY_URL, timeout=30) as response:
        catalog = build_catalog(response.read())
    if len(catalog) < 400:
        raise RuntimeError(f"Expected at least 400 GTFOBins entries, found {len(catalog)}")
    OUTPUT_PATH.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(catalog)} GTFOBins entries to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
