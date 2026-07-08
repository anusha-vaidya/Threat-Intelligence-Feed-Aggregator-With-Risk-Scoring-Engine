from typing import List
from .schema import IOC

HIGH_RISK_COUNTRIES = {"Russia", "China", "Iran", "North Korea"}
HIGH_RISK_ASN_KEYWORDS = ["hosting", "vpn", "tor", "bulletproof"]

def score_ioc(ioc: IOC) -> float:
    score = 0

    # Threat type weight
    if ioc.threat_type:
        if "malware" in ioc.threat_type.lower():
            score += 40
        elif "phishing" in ioc.threat_type.lower():
            score += 30
        else:
            score += 10

    # Geo risk
    country = ioc.enrichment.get("country")
    if country in HIGH_RISK_COUNTRIES:
        score += 20

    # ASN risk
    org = ioc.enrichment.get("org", "")
    if any(keyword in str(org).lower() for keyword in HIGH_RISK_ASN_KEYWORDS):
        score += 15

    # Feed frequency
    freq = ioc.enrichment.get("feed_frequency", 1)
    score += min(freq * 5, 25)

    return min(score, 100)


def score_iocs(iocs: List[IOC]) -> List[IOC]:
    for ioc in iocs:
        ioc.risk_score = score_ioc(ioc)
    return iocs
