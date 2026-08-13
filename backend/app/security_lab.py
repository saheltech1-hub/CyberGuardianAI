"""Unified defensive security-lab triage helpers."""

from .ioc import extract_iocs
from .log_analyzer import summarize_lines
from .mitre import map_techniques
from .security_analysis import analyze_event


def triage(text: str) -> dict:
    """Correlate event analysis, IOCs, log markers and ATT&CK mappings."""
    analysis = analyze_event(text)
    return {
        "risk": analysis["risk"],
        "indicators": analysis["indicators"],
        "recommendations": analysis["recommendations"],
        "iocs": extract_iocs(text),
        "mitre": map_techniques(text),
        "log_summary": summarize_lines(text.splitlines()),
    }
