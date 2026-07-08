import json
import requests
from typing import List
from .schema import IOC

GEO_API = "https://ipapi.co/{}/json/"

def enrich_geo(ioc: IOC) -> dict:
    """
    Adds geo information for IP-based IOCs.
    """
    if ioc.indicator_type != "ip":
        return {}

    try:
        url = GEO_API.format(ioc.indicator_value)
        response = requests.get(url)
        data = response.json()

        return {
            "country": data.get("country_name"),
            "region": data.get("region"),
            "asn": data.get("asn"),
            "org": data.get("org")
        }
    except Exception:
        return {}


def enrich_frequency(ioc: IOC, feed_counts: dict) -> dict:
    """
    Adds frequency score based on how many feeds reported the IOC.
    """
    key = (ioc.indicator_type, ioc.indicator_value)
    return {"feed_frequency": feed_counts.get(key, 1)}


def compute_feed_counts(iocs: List[IOC]) -> dict:
    """
    Counts how many times each IOC appears across feeds.
    """
    counts = {}
    for ioc in iocs:
        key = (ioc.indicator_type, ioc.indicator_value)
        counts[key] = counts.get(key, 0) + 1
    return counts


def enrich_iocs(iocs: List[IOC]) -> List[IOC]:
    """
    Full enrichment pipeline.
    """
    feed_counts = compute_feed_counts(iocs)

    enriched = []
    for ioc in iocs:
        geo_data = enrich_geo(ioc)
        freq_data = enrich_frequency(ioc, feed_counts)

        ioc.enrichment = {
            **geo_data,
            **freq_data
        }

        enriched.append(ioc)

    return enriched


def save_enriched_iocs(iocs: List[IOC], path="data/enriched/iocs.json"):
    json_data = [ioc.dict() for ioc in iocs]
    with open(path, "w") as f:
        json.dump(json_data, f, indent=2)
