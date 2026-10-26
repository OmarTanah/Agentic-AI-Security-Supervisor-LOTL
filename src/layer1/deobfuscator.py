"""Multi-layer shell command de-obfuscation (Layer 1).

Applies a fixed pipeline repeatedly (up to MAX_DEPTH passes) until the command
stops changing. Every transformation that fires is recorded in `flags` so the
agent (Layer 2) can treat "this command was obfuscated" as evidence.
"""
import base64
import binascii
import re

MAX_DEPTH = 3

_B64_PIPE = re.compile(
    r"""echo\s+(?:-n\s+)?['"]?([A-Za-z0-9+/=]{8,})['"]?\s*\|\s*base64\s+(?:-d|--decode)(?:\s*\|\s*(?:ba|z|da)?sh)?""")
_B64_HERE = re.compile(
    r"""base64\s+(?:-d|--decode)\s*<<<\s*['"]?([A-Za-z0-9+/=]{8,})['"]?""")
_HEX_ESC = re.compile(r"\\x([0-9a-fA-F]{2})")
_ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.)*)'")
_EMPTY_QUOTES = re.compile(r"(?<=\w)(?:''|\"\")(?=\w)")
_BACKSLASH_LETTER = re.compile(r"\\(?=[A-Za-z])")
_IFS = re.compile(r"\$\{IFS(?:%%[^}]*)?\}|\$IFS(?:\$\d)?")
_WS = re.compile(r"\s+")


def _try_b64(blob: str):
    try:
        raw = base64.b64decode(blob, validate=True)
        text = raw.decode("utf-8")
        if text.isprintable() or "\n" in text:
            return text
    except (binascii.Error, UnicodeDecodeError, ValueError):
        pass
    return None


def _decode_ansi_c(match: re.Match) -> str:
    body = match.group(1)
    body = _HEX_ESC.sub(lambda m: chr(int(m.group(1), 16)), body)
    body = re.sub(r"\\([0-7]{1,3})", lambda m: chr(int(m.group(1), 8)), body)
    return body


def _one_pass(cmd: str, flags: set) -> str:
    out = cmd

    def b64_sub(m):
        decoded = _try_b64(m.group(1))
        if decoded is None:
            return m.group(0)
        flags.add("base64")
        return decoded

    out = _B64_PIPE.sub(b64_sub, out)
    out = _B64_HERE.sub(b64_sub, out)

    if _ANSI_C.search(out):
        out = _ANSI_C.sub(_decode_ansi_c, out)
        flags.add("ansi_c_quoting")
    if _HEX_ESC.search(out):
        out = _HEX_ESC.sub(lambda m: chr(int(m.group(1), 16)), out)
        flags.add("hex_escape")
    if _IFS.search(out):
        out = _IFS.sub(" ", out)
        flags.add("ifs_substitution")
    if _EMPTY_QUOTES.search(out):
        out = _EMPTY_QUOTES.sub("", out)
        flags.add("quote_splitting")
    if _BACKSLASH_LETTER.search(out) and "\\n" not in out:
        out = _BACKSLASH_LETTER.sub("", out)
        flags.add("backslash_insertion")
    return _WS.sub(" ", out).strip()


def deobfuscate(command: str, max_depth: int = MAX_DEPTH):
    """Return (clean_command, sorted_flags, passes_used)."""
    flags: set = set()
    current = _WS.sub(" ", command or "").strip()
    passes = 0
    for _ in range(max_depth):
        nxt = _one_pass(current, flags)
        if nxt == current:
            break
        current = nxt
        passes += 1
    if passes >= 2:
        flags.add("multi_layer")
    return current, sorted(flags), passes
