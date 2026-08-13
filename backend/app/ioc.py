from ipaddress import ip_address
import re

DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.I)
URL_RE = re.compile(r"\bhttps?://[^\s]+", re.I)
HASH_RE = re.compile(r"\b[a-f0-9]{32}(?:[a-f0-9]{8}|[a-f0-9]{24}|[a-f0-9]{32})?\b", re.I)


def extract_iocs(text: str) -> dict[str, list[str]]:
    ips: list[str] = []
    for token in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        try:
            ip_address(token)
            ips.append(token)
        except ValueError:
            pass
    return {"ipv4": sorted(set(ips)), "domains": sorted(set(DOMAIN_RE.findall(text))), "urls": sorted(set(URL_RE.findall(text))), "hashes": sorted(set(HASH_RE.findall(text)))}
