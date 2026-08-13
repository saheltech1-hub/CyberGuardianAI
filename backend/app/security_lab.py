"""Unified defensive security-lab triage helpers."""

from .ioc import extract_iocs
from .log_analyzer import summarize_lines
from .mitre import map_techniques
from .security_analysis import analyze_event


def triage(text: str) -> dict:
    """Correlate event analysis, IOCs, log markers and ATT&CK mappings.

    Returns a dictionary with the unified triage contract. Safe for empty input.
    """
    if not text:
        analysis = {"risk": "low", "indicators": [], "recommendations": [
            "No suspicious indicators detected.",
            "Provide more context or logs for deeper triage.",
        ]}
    else:
        analysis = analyze_event(text)

    return {
        "risk": analysis.get("risk", "low"),
        "indicators": analysis.get("indicators", []),
        "recommendations": analysis.get("recommendations", []),
        "iocs": extract_iocs(text or ""),
        "mitre": map_techniques(text or ""),
        "log_summary": summarize_lines((text or "").splitlines()),
    }
