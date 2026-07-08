"""
Threat‑Intelligence Feed Aggregator & Risk Scoring Engine
Full Pipeline Runner (v1.0)

This script:
1. Collects IOCs from URLhaus and ThreatFox
2. Aggregates and deduplicates them
3. Enriches with geo, ASN, and frequency data
4. Scores each IOC
5. Saves final outputs to /data/enriched/
6. Generates a daily markdown report
"""

import os
import json
import pandas as pd

from src.collect_urlhaus import collect_urlhaus
from src.collect_threatfox import collect_threatfox
from src.aggregate_feeds import aggregate_feeds
from src.enrich import enrich_iocs, save_enriched_iocs
from src.score import score_iocs


def ensure_directories():
    """
    Ensures all required directories exist.
    """
    dirs = [
        "data/raw",
        "data/normalized",
        "data/enriched",
        "reports"
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)


def run_pipeline():
    print("\n=== Threat Intelligence Pipeline Started ===\n")

    ensure_directories()

    # ---------------------------
    # 1. Collect URLhaus IOCs
    # ---------------------------
    print("Collecting URLhaus IOCs...")
    try:
        urlhaus_iocs = collect_urlhaus()
        print(f"URLhaus IOCs collected: {len(urlhaus_iocs)}")
    except Exception as e:
        print(f"ERROR collecting URLhaus feed: {e}")
        urlhaus_iocs = []

    # ---------------------------
    # 2. Collect ThreatFox IOCs
    # ---------------------------
    print("\nCollecting ThreatFox IOCs...")
    try:
        threatfox_iocs = collect_threatfox()
        print(f"ThreatFox IOCs collected: {len(threatfox_iocs)}")
    except Exception as e:
        print(f"ERROR collecting ThreatFox feed: {e}")
        threatfox_iocs = []

    # ---------------------------
    # 3. Aggregate & Deduplicate
    # ---------------------------
    print("\nAggregating and deduplicating feeds...")
    try:
        normalized_iocs = aggregate_feeds()
        print(f"Normalized IOC count: {len(normalized_iocs)}")
    except Exception as e:
        print(f"ERROR aggregating feeds: {e}")
        normalized_iocs = []

    # ---------------------------
    # 4. Enrichment
    # ---------------------------
    print("\nEnriching IOCs...")
    try:
        enriched_iocs = enrich_iocs(normalized_iocs)
        save_enriched_iocs(enriched_iocs)
        print(f"Enriched IOC count: {len(enriched_iocs)}")
    except Exception as e:
        print(f"ERROR enriching IOCs: {e}")
        enriched_iocs = []

    # ---------------------------
    # 5. Risk Scoring
    # ---------------------------
    print("\nScoring IOCs...")
    try:
        scored_iocs = score_iocs(enriched_iocs)
    except Exception as e:
        print(f"ERROR scoring IOCs: {e}")
        scored_iocs = []

    # ---------------------------
    # 6. Convert to DataFrame
    # ---------------------------
    print("\nConverting to DataFrame...")
    try:
        df = pd.DataFrame([ioc.dict() for ioc in scored_iocs])
        print("DataFrame created.")
    except Exception as e:
        print(f"ERROR converting to DataFrame: {e}")
        df = pd.DataFrame()

    # ---------------------------
    # 7. Save final scored dataset
    # ---------------------------
    print("\nSaving final scored dataset...")
    try:
        df.to_csv("data/enriched/iocs_scored.csv", index=False)
        print("Saved: data/enriched/iocs_scored.csv")
    except Exception as e:
        print(f"ERROR saving final CSV: {e}")

    # ---------------------------
    # 8. Generate daily report
    # ---------------------------
    print("\nGenerating daily report...")
    try:
        high_risk = df[df["risk_score"] >= 80]

        with open("reports/daily_report.md", "w") as f:
            f.write("# Daily Threat Intelligence Report\n\n")
            f.write("## High-Risk IOCs (Score ≥ 80)\n\n")

            for _, row in high_risk.iterrows():
                f.write(
                    f"- {row['indicator_type']}: {row['indicator_value']} "
                    f"(score: {row['risk_score']})\n"
                )

        print("Saved: reports/daily_report.md")
    except Exception as e:
        print(f"ERROR generating report: {e}")

    print("\n=== Pipeline Completed Successfully ===\n")


if __name__ == "__main__":
    run_pipeline()
