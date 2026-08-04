import re

def sanitize_command(raw_cmd: str) -> str:
    """Strips ANSI escape codes, unprintable chars, and normalizes space."""
    if not isinstance(raw_cmd, str):
        return ""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    clean = ansi_escape.sub('', raw_cmd)
    clean = "".join(ch for ch in clean if ch.isprintable())
    return " ".join(clean.strip().split())
