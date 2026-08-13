"""Small, deterministic MITRE ATT&CK mapping for defensive triage."""

KEYWORD_TECHNIQUES = {
    "powershell": ("T1059.001", "PowerShell"),
    "cmd.exe": ("T1059.003", "Windows Command Shell"),
    "scheduled task": ("T1053.005", "Scheduled Task/Job: Scheduled Task"),
    "service": ("T1543.003", "Windows Service"),
    "credential dumping": ("T1003", "OS Credential Dumping"),
}


def map_techniques(text: str) -> list[dict[str, str]]:
    lowered = text.lower()
    found = []
    for keyword, (technique_id, name) in KEYWORD_TECHNIQUES.items():
        if keyword in lowered:
            found.append({"id": technique_id, "name": name, "matched": keyword})
    return found
