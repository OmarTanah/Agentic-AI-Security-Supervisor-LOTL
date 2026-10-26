"""Event normalization (Layer 1).

Converts a decoded Wazuh EVENT (JSON, not an alert) into the canonical event consumed by the ReAct
agent. Key design points:
  * the command text is ALWAYS labelled `untrusted` (attacker-controlled input),
    which downstream prompts must wrap in delimiters (anti prompt-injection);
  * severity is computed deterministically from Wazuh level + heuristics, never
    by the LLM;
  * a stable event key is produced for de-duplication.
"""
import hashlib
import re
from datetime import datetime, timezone

from .deobfuscator import deobfuscate

SHELL_NET_PATTERNS = [
    r"/dev/(tcp|udp)/", r"\bnc(at)?\b.*\s-e\b", r"\bsocat\b.*exec", r"\bmkfifo\b",
    r"\bbash\s+-i\b", r"\b(curl|wget)\b.*\|\s*(ba|z|da)?sh\b",
    r"\bpython[23]?\s+-c\b.*socket", r"\bperl\s+-e\b.*socket",
]
PRIV_ESC_PATTERNS = [
    r"\bsudo\b.*\b(find|vim?|awk|nano|less|more|tar|env|nmap|perl|python[23]?)\b.*(-exec|:!|system|/bin/(ba)?sh|--checkpoint-action)",
    r"\bchmod\s+[0-7]*[4-7][0-7]{2}\b.*", r"\bchmod\s+u\+s\b",
]
INJECTION_HINTS = [
    r"ignore (all )?(previous|prior) instructions", r"you are now", r"system prompt",
    r"classify (this|it) as benign", r"\bdisable_user\b", r"\bblock_ip\b", r"\bisolate_host\b",
]
_SEV_ORDER = ["low", "medium", "high", "critical"]


def _get(d, path, default=None):
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


_SUDO_LOG = re.compile(r"sudo:\s+(?P<user>\S+)\s*:.*?(?:PWD=(?P<pwd>\S+)\s*;\s*)?USER=(?P<dst>\S+)\s*;\s*COMMAND=(?P<cmd>.+)$")
_AUDIT_ARG = re.compile(r'\ba(\d+)=(?:"([^"]*)"|([0-9A-Fa-f]+))')


def _parse_full_log(event: dict):
    """Fallback when Wazuh decoders did not populate `data` (raw event / archives)."""
    log = event.get("full_log") or ""
    m = _SUDO_LOG.search(log)
    if m:
        event.setdefault("data", {}).update({"srcuser": m["user"], "dstuser": m["dst"],
                                             "pwd": m["pwd"], "command": m["cmd"].strip()})
        return
    if "type=EXECVE" in log:
        args = {}
        for idx, quoted, hexval in _AUDIT_ARG.findall(log):
            if quoted:
                args[f"a{idx}"] = quoted
            else:  # auditd hex-encodes args containing special chars
                try:
                    args[f"a{idx}"] = bytes.fromhex(hexval).decode("utf-8", "replace")
                except ValueError:
                    args[f"a{idx}"] = hexval
        if args:
            event.setdefault("data", {}).setdefault("audit", {})["execve"] = args


def _extract_command(alert: dict):
    """Return (command, source). Handles sudo and auditd EXECVE shapes."""
    if not (alert.get("data") or {}).get("command") and not _get(alert, "data.audit.execve"):
        _parse_full_log(alert)
    data = alert.get("data", {}) or {}
    if data.get("command"):                       # sudo decoder
        return data["command"], "sudo"
    execve = _get(data, "audit.execve")
    if isinstance(execve, dict):                  # auditd: a0, a1, a2 ...
        args = [v for k, v in sorted(execve.items(),
                key=lambda kv: int(kv[0][1:]) if kv[0][1:].isdigit() else 0) if k != "argc"]
        if args:
            return " ".join(args), "auditd"
    if _get(data, "audit.command"):
        return data["audit"]["command"], "auditd"
    if _get(data, "win.eventdata.commandLine"):   # Sysmon (kept for Windows endpoint)
        return data["win"]["eventdata"]["commandLine"], "sysmon"
    return None, "unknown"


def _bump(sev: str, steps: int = 1) -> str:
    return _SEV_ORDER[min(_SEV_ORDER.index(sev) + steps, len(_SEV_ORDER) - 1)]


def compute_severity(command: str, flags: list, user: str, source: str = ""):
    # Wazuh's sudo decoder strips the leading "sudo"; restore it for pattern matching.
    if source == "sudo" and not command.startswith("sudo "):
        command = "sudo " + command
    reasons = []
    sev = "low"  # raw events carry no Wazuh rule level; severity is purely heuristic
    if any(re.search(p, command, re.I) for p in SHELL_NET_PATTERNS):
        sev = _bump(sev); reasons.append("network_shell_pattern")
    if any(re.search(p, command, re.I) for p in PRIV_ESC_PATTERNS):
        sev = _bump(sev); reasons.append("priv_esc_pattern")
    if flags:
        sev = _bump(sev); reasons.append("obfuscation:" + ",".join(flags))
    if user == "root" and sev == "low":
        sev = "medium"; reasons.append("root_context")
    return sev, reasons


def event_key(host: str, user: str, clean_cmd: str) -> str:
    return hashlib.sha256(f"{host}|{user}|{clean_cmd}".encode()).hexdigest()


def normalize(alert: dict):
    """Wazuh alert -> canonical event dict, or None if no command is present."""
    command, source = _extract_command(alert)
    if not command:
        return None
    clean, flags, passes = deobfuscate(command)
    host = _get(alert, "agent.name", "unknown-host")
    user = _get(alert, "data.srcuser") or _get(alert, "data.audit.auid") or _get(alert, "data.audit.uid") or "unknown"
    severity, reasons = compute_severity(clean, flags, user, source)
    inj = [p for p in INJECTION_HINTS if re.search(p, command, re.I)]
    key = event_key(host, user, clean)
    return {
        "event_id": hashlib.sha256((key + str(alert.get("id", alert.get("timestamp", "")))).encode()).hexdigest()[:16],
        "dedup_key": key,
        "timestamp": alert.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "host": host,
        "agent_id": _get(alert, "agent.id", "000"),
        "user": user,
        "effective_user": _get(alert, "data.dstuser", user),
        "cwd": _get(alert, "data.pwd"),
        "tty": _get(alert, "data.tty"),
        "source": source,
        "command_raw": command,
        "command_clean": clean,
        "obfuscation_flags": flags,
        "deobf_passes": passes,
        "decoder": _get(alert, "decoder.name"),
        "wazuh_rule_id": _get(alert, "rule.id"),  # optional: only if a rule happened to match
        "severity": severity,
        "severity_reasons": reasons,
        "provenance": {"command": "untrusted", "metadata": "wazuh_decoded",
                       "injection_hints": inj},
    }
