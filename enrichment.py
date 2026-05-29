"""IP reputation and ASN enrichment helpers for HoneyPot v3.

The module is intentionally dependency-free and safe-by-default: private/local IPs
are handled locally, external lookups are optional, and no API tokens are exposed
through API responses.
"""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from ipaddress import ip_address


TIMEOUT_SECONDS = float(os.environ.get("HONEYPOT_ENRICHMENT_TIMEOUT_SECONDS", "4"))
DEFAULT_PROVIDER = os.environ.get("HONEYPOT_ENRICHMENT_PROVIDER", "ip-api").strip().lower()
ENABLE_EXTERNAL = os.environ.get("HONEYPOT_ENRICHMENT_ENABLED", "true").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}


def is_public_ip(ip: str) -> bool:
    try:
        parsed = ip_address(ip)
    except ValueError:
        return False
    return not any(
        [
            parsed.is_private,
            parsed.is_loopback,
            parsed.is_link_local,
            parsed.is_multicast,
            parsed.is_reserved,
            parsed.is_unspecified,
        ]
    )


def local_enrichment(ip: str) -> dict:
    return {
        "asn": None,
        "asn_org": "Local Network" if ip else "Unknown",
        "reputation_score": 0,
        "reputation_level": "internal",
        "reputation_flags": ["non_public_ip"],
        "enrichment_provider": "local",
    }


def reputation_from_ip_api(data: dict) -> tuple[int, list[str]]:
    flags: list[str] = []
    score = 0
    if data.get("proxy"):
        flags.append("proxy_or_vpn")
        score += 35
    if data.get("hosting"):
        flags.append("hosting_provider")
        score += 25
    if data.get("mobile"):
        flags.append("mobile_network")
        score += 5
    org_text = " ".join(str(data.get(k) or "") for k in ("isp", "org", "as")).lower()
    noisy_markers = ("cloud", "hosting", "vps", "vpn", "proxy", "tor", "colo", "datacenter", "data center")
    if any(marker in org_text for marker in noisy_markers):
        flags.append("infrastructure_asn")
        score += 15
    return min(score, 100), sorted(set(flags))


def level_for_score(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "suspicious"
    if score > 0:
        return "low"
    return "unknown"


def enrich_with_ip_api(ip: str) -> dict | None:
    fields = "status,country,city,regionName,lat,lon,isp,org,as,asname,query,proxy,hosting,mobile,reverse"
    url = "http://ip-api.com/json/{}?fields={}".format(urllib.parse.quote(ip), urllib.parse.quote(fields))
    with urllib.request.urlopen(url, timeout=TIMEOUT_SECONDS) as response:
        data = json.loads(response.read().decode("utf-8"))
    if data.get("status") != "success":
        return None
    score, flags = reputation_from_ip_api(data)
    as_value = data.get("as") or ""
    asn = None
    if isinstance(as_value, str) and as_value.upper().startswith("AS"):
        asn = as_value.split()[0].upper()
    return {
        "country": data.get("country"),
        "city": data.get("city"),
        "region": data.get("regionName"),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
        "isp": data.get("isp"),
        "asn": asn,
        "asn_org": data.get("asname") or data.get("org") or data.get("isp"),
        "reputation_score": score,
        "reputation_level": level_for_score(score),
        "reputation_flags": flags,
        "enrichment_provider": "ip-api",
        "raw_geo": json.dumps(data, sort_keys=True),
    }


def enrich_ip(ip: str) -> dict:
    if not ip or not is_public_ip(ip):
        return local_enrichment(ip)
    if not ENABLE_EXTERNAL:
        result = local_enrichment(ip)
        result.update({"asn_org": "External enrichment disabled", "enrichment_provider": "disabled"})
        return result
    if DEFAULT_PROVIDER != "ip-api":
        result = local_enrichment(ip)
        result.update({"asn_org": "Unsupported enrichment provider", "enrichment_provider": DEFAULT_PROVIDER or "unknown"})
        return result
    try:
        enriched = enrich_with_ip_api(ip)
    except Exception:
        enriched = None
    if not enriched:
        result = local_enrichment(ip)
        result.update({"asn_org": "Enrichment unavailable", "enrichment_provider": "ip-api"})
        return result
    return enriched
