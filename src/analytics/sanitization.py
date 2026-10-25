import re

def sanitize_command(raw_cmd: str) -> str:
    """Strips ANSI escape codes, unprintable chars, and normalizes space."""
    if not isinstance(raw_cmd, str):
        return ""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    clean = ansi_escape.sub('', raw_cmd)
    clean = "".join(ch for ch in clean if ch.isprintable())
    return " ".join(clean.strip().split())


_URL = re.compile(r"https?://[^\s'\"<>|;&]+")


def extract_urls(commands) -> list:
    """Unique URLs (in order of first appearance) mentioned in a session's commands, e.g. malware
    dropper URLs from wget/curl. The same URL across sessions is a strong attribution signal."""
    seen = {}
    for cmd in commands:
        for url in _URL.findall(str(cmd)):
            seen.setdefault(url, None)
    return list(seen)
