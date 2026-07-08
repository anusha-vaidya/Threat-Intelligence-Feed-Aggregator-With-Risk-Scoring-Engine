import requests
import json
from datetime import datetime
from typing import List
from .schema import IOC

THREATFOX_JSON_URL = "https://threatfox.abuse.ch/export/json/"

def fetch_threatfox_json() -> dict:
    """
    Downloads the ThreatFox JSON feed and returns it as a dictionary.
    """
    response = requests.get(THREATFOX_JSON_URL)
    response.raise_for_status()
    return response.json()


def normalize_threatfox(data: dict) -> List[IOC]:
    """
    Converts ThreatFox JSON entries into IOC objects using the unified schema.
    """
    iocs = []

    entries = data.get("data", [])

    for entry in entries:
        try:
            ioc = IOC(
                indicator_type=entry.get("ioc_type", "").lower(),
                indicator_value=entry.get("ioc", ""),
                source_feed="threatfox",
                threat_type=entry.get("threat_type", None),
                first_seen=datetime.strptime(entry["first_seen"], "%Y-%m-%d") if entry.get("first_seen") else None,
                last_seen=datetime.strptime(entry["last_seen"], "%Y-%m-%d") if entry.get("last_seen") else None,
                confidence=entry.get("confidence_level", None),
                tags=entry.get("tags", []),
                enrichment={},
                risk_score=None
            )
            iocs.append(ioc)
        except Exception:
            continue

    return iocs


def save_raw_data(data: dict, path: str = "data/raw/threatfox_raw.json"):
    """
    Saves the raw JSON data into the repository.
    """
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def collect_threatfox() -> List[IOC]:
    """
    Full pipeline:
    - Fetch JSON
    - Save raw data
    - Normalize into IOC objects
    """
    data = fetch_threatfox_json()
    save_raw_data(data)
    iocs = normalize_threatfox(data)
    return iocs
