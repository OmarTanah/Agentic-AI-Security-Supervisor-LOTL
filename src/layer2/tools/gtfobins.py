import json
import re
from pathlib import Path
from typing import Any

from rapidfuzz import fuzz


_CATALOG_PATH = Path(__file__).resolve().parents[3] / "data" / "gtfobins.json"
with _CATALOG_PATH.open(encoding="utf-8") as catalog_file:
    _CATALOG: dict[str, dict[str, object]] = json.load(catalog_file)

_PAYLOADS_PATH = Path(__file__).resolve().parents[3] / "data" / "gtfobins_payloads.json"
with _PAYLOADS_PATH.open(encoding="utf-8") as payload_file:
    _PAYLOADS: dict[str, list[dict[str, Any]]] = json.load(payload_file)

_SUSPICIOUS_TOKENS = (
    "-exec",
    "--checkpoint-action",
    "| sh",
    "| bash",
    "/dev/tcp",
    "-c",
    "system(",
    "exec(",
)


def _actual_command(binary: str, command: str) -> str:
    """Remove common command wrappers and return the binary invocation."""
    normalized = " ".join(command.split())
    normalized = re.sub(r"^sudo(?:\s+-[A-Za-z0-9_=.-]+)*\s+", "", normalized)
    binary_name = Path(binary).name
    match = re.search(rf"(?:^|\s)(?:\S+/)?{re.escape(binary_name)}(?:\s|$)", normalized)
    return normalized[match.start():].strip() if match else normalized


def _payload_candidates(binary: str) -> list[str]:
    """Render catalog payload templates into comparable command strings."""
    candidates: list[str] = []
    replacements = {
        "{command}": binary,
        "{shell}": "/bin/sh",
        "{cat}": "cat",
        "{lfile}": "/etc/passwd",
        "{ctrl_c}": "",
        "{ctrl_d}": "",
    }
    for method in _PAYLOADS.get(binary, []):
        payload = str(method.get("payload", ""))
        args = method.get("args", [])
        rendered = " ".join([payload, *(str(arg) for arg in args)]).strip()
        for placeholder, value in replacements.items():
            rendered = rendered.replace(placeholder, value)
        candidates.append(rendered)
        candidates.append(re.sub(r"\s+(?:-p|-quit)\b", "", rendered))
    return candidates


def _legacy_check(binary: str) -> dict[str, object]:
    """Preserve the original one-argument API for existing callers."""
    binary_name = Path(binary).name
    entry = _CATALOG.get(binary_name)
    if entry is None:
        return {"is_gtfobin": False, "functions": [], "risk": "none"}
    return {"is_gtfobin": True, "functions": entry["functions"], "risk": entry["risk"]}


def check_gtfobins(binary: str, command: str | None = None) -> dict[str, object]:
    """Match a command against GTFOBins capabilities and payloads."""
    if command is None:
        return _legacy_check(binary)

    binary_name = Path(binary).name
    entry = _CATALOG.get(binary_name)
    if entry is None:
        return {"binary_in_gtfobins": False, "risk_contribution": 0.0}

    actual_command = _actual_command(binary_name, command)
    similarities = [fuzz.ratio(actual_command, payload) for payload in _payload_candidates(binary_name)]
    best_similarity = max(similarities, default=0.0)
    known_payload_match = "exact" if best_similarity == 100 else "partial" if best_similarity >= 85 else "none"
    suspicious_args = [token for token in _SUSPICIOUS_TOKENS if token in actual_command]
    functions = [str(function) for function in entry.get("functions", [])]
    risk_contribution = {
        "exact": 0.25,
        "partial": 0.15,
    }.get(known_payload_match, 0.10 if "shell" in functions and suspicious_args else 0.0)

    return {
        "binary_in_gtfobins": True,
        "capability": "shell" if "shell" in functions else (functions[0] if functions else "none"),
        "known_payload_match": known_payload_match,
        "suspicious_args": suspicious_args,
        "risk_contribution": risk_contribution,
    }
