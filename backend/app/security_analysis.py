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
