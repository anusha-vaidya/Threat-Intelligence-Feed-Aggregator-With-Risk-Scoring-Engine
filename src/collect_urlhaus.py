import pandas as pd
import requests
from io import StringIO
from datetime import datetime
from typing import List
from .schema import IOC

URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv/"

def fetch_urlhaus_csv() -> pd.DataFrame:
    """
    Downloads the URLhaus CSV feed and returns it as a pandas DataFrame.
    """
    response = requests.get(URLHAUS_CSV_URL)
    response.raise_for_status()

    csv_data = response.text
    df = pd.read_csv(StringIO(csv_data), comment="#")
    return df


def normalize_urlhaus(df: pd.DataFrame) -> List[IOC]:
    """
    Converts URLhaus CSV rows into IOC objects using the unified schema.
    """
    iocs = []

    for _, row in df.iterrows():
        try:
            ioc = IOC(
                indicator_type="url",
                indicator_value=row["url"],
                source_feed="urlhaus",
                threat_type=row.get("threat", None),
                first_seen=datetime.strptime(row["date_added"], "%Y-%m-%d"),
                last_seen=datetime.strptime(row["date_added"], "%Y-%m-%d"),
                confidence=None,
                tags=[row.get("url_status", None)],
                enrichment={},
                risk_score=None
            )
            iocs.append(ioc)
        except Exception:
            continue

    return iocs


def save_raw_data(df: pd.DataFrame, path: str = "data/raw/urlhaus_raw.csv"):
    """
    Saves the raw CSV data into the repository.
    """
    df.to_csv(path, index=False)


def collect_urlhaus() -> List[IOC]:
    """
    Full pipeline:
    - Fetch CSV
    - Save raw data
    - Normalize into IOC objects
    """
    df = fetch_urlhaus_csv()
    save_raw_data(df)
    iocs = normalize_urlhaus(df)
    return iocs
