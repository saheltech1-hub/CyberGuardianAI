from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Finding:
    indicator: str
    severity: str
    category: str


PATTERNS = (
    (re.compile(r"\bpowershell(?:\.exe)?\b", re.I), "PowerShell", "medium", "execution"),
    (re.compile(r"\b(?:cmd\.exe|wscript\.exe|cscript\.exe)\b", re.I), "Windows scripting utility", "medium", "execution"),
    (re.compile(r"\b(?:curl|wget)\b", re.I), "Network utility", "low", "network"),
    (re.compile(r"\b(?:credential|password|secret|token)\b", re.I), "Credential-related term", "medium", "credential-access"),
    (re.compile(r"\b(?:base64|frombase64string)\b", re.I), "Encoding reference", "low", "defense-evasion"),
)


def analyze_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for pattern, indicator, severity, category in PATTERNS:
        if pattern.search(text):
            findings.append(Finding(indicator, severity, category))
    return findings


def analyze_event(text: str) -> dict:
    """Public analysis function returning the unified contract used by Security Lab.

    Returns a dict with keys: risk, indicators, recommendations.
    This function is deterministic, offline, and does not execute any code or
    reach the network.
    """
    if not text:
        return {"risk": "low", "indicators": [], "recommendations": [
            "No suspicious indicators detected.",
            "Ensure logs and telemetry are available for further analysis.",
        ]}

    findings = analyze_text(text)
    indicators = sorted({f.indicator for f in findings})

    # Determine risk: high if any 'high' severity (none currently), medium if any findings, else low
    if any(getattr(f, "severity", "") == "high" for f in findings):
        risk = "high"
    elif findings:
        risk = "medium"
    else:
        risk = "low"

    recommendations = [
        "Validate the event against trusted logs and endpoint telemetry.",
        "Do not treat keyword matches alone as proof of compromise.",
    ]
    # Add targeted recommendations based on categories
    categories = {f.category for f in findings}
    if "execution" in categories:
        recommendations.append("Investigate process execution and parent/child relationships on endpoints.")
    if "credential-access" in categories:
        recommendations.append("Rotate affected credentials and review recent authentication logs.")

    return {"risk": risk, "indicators": indicators, "recommendations": recommendations}
