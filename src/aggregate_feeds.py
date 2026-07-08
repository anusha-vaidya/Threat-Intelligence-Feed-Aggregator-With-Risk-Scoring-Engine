import json
from typing import List
from .collect_urlhaus import collect_urlhaus
from .collect_threatfox import collect_threatfox
from .schema import IOC

def deduplicate_iocs(iocs: List[IOC]) -> List[IOC]:
    """
    Removes duplicate IOCs based on indicator_value + indicator_type.
    """
    seen = set()
    unique_iocs = []

    for ioc in iocs:
        key = (ioc.indicator_type, ioc.indicator_value)
        if key not in seen:
            seen.add(key)
            unique_iocs.append(ioc)

    return unique_iocs


def save_normalized_iocs(iocs: List[IOC], path: str = "data/normalized/iocs.json"):
    """
    Saves normalized IOC objects into a JSON file.
    """
    json_data = [ioc.dict() for ioc in iocs]

    with open(path, "w") as f:
        json.dump(json_data, f, indent=2)


def aggregate_feeds() -> List[IOC]:
    """
    Full pipeline:
    - Collect from URLhaus
    - Collect from ThreatFox
    - Merge
    - Deduplicate
    - Save normalized output
    """
    urlhaus_iocs = collect_urlhaus()
    threatfox_iocs = collect_threatfox()

    merged = urlhaus_iocs + threatfox_iocs
    deduped = deduplicate_iocs(merged)

    save_normalized_iocs(deduped)

    return deduped
