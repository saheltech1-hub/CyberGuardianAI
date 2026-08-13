"""Offline log triage helpers. No network access or command execution."""

from collections import Counter


def summarize_lines(lines: list[str]) -> dict:
    """Return deterministic counts for common security-relevant log markers."""
    markers = {
        "failed_auth": ("failed password", "authentication failure", "login failed"),
        "privilege": ("sudo", "administrator", "privilege"),
        "network": ("connection", "connect", "remote address"),
        "error": ("error", "exception", "denied"),
    }
    counts = Counter()
    for line in lines:
        lowered = line.lower()
        for category, words in markers.items():
            if any(word in lowered for word in words):
                counts[category] += 1
    return {"line_count": len(lines), "categories": dict(counts)}
