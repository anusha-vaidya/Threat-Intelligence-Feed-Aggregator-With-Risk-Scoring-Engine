"""
Threat‑Intelligence Feed Aggregator & Risk Scoring Engine
Full Pipeline Script (v0.1)

This script:
1. Collects IOCs from URLhaus and ThreatFox
2. Aggregates and deduplicates them
3. Enriches with geo, ASN, and frequency data
4. Scores each IOC
5. Saves final outputs to /data/enriched/
"""

import json
import pandas as pd

from src.collect_urlhaus import collect_urlhaus
from src.collect_threatfox import collect_threatfox
from src.aggregate_feeds import aggregate_feeds
from src.enrich import enrich_iocs, save_enriched_iocs
from src.score import score_iocs


def run_pipeline():
    print("Collecting URLhaus IOCs...")
    urlhaus_iocs = collect_urlhaus()
    print(f"URLhaus IOCs collected: {len(urlhaus_iocs)}")

    print("Collecting ThreatFox IOCs...")
    threatfox_iocs = collect_threatfox()
    print(f"ThreatFox IOCs collected: {len(threatfox_iocs)}")

    print("Aggregating and deduplicating feeds...")
    normalized_iocs = aggregate_feeds()
    print(f"Normalized IOC count: {len(normalized_iocs)}")

    print("Enriching IOCs...")
    enriched_iocs = enrich_iocs(normalized_iocs)
    save_enriched_iocs(enriched_iocs)
    print(f"Enriched IOC count: {len(enriched_iocs)}")

    print("Scoring IOCs...")
    scored_iocs = score_iocs(enriched_iocs)

    print("Converting to DataFrame...")
    df = pd.DataFrame([ioc.dict() for ioc in scored_iocs])

    print("Saving final scored dataset...")
    df.to_csv("data/enriched/iocs_scored.csv", index=False)

    print("Generating daily report...")
    high_risk = df[df["risk_score"] >= 80]

    with open("reports/daily_report.md", "w") as f:
        f.write("# Daily Threat Intelligence Report\n\n")
        f.write("## High-Risk IOCs (Score ≥ 80)\n\n")
        for _, row in high_risk.iterrows():
            f.write(f"- {row['indicator_type']}: {row['indicator_value']} (score: {row['risk_score']})\n")

    print("Pipeline completed successfully.")


if __name__ == "__main__":
    run_pipeline()
