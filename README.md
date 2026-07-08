# Threat-Intelligence-Feed-Aggregator-With-Risk-Scoring-Engine
A fully automated, multi‑feed cybersecurity pipeline that collects Indicators of Compromise (IOCs), normalizes them, enriches them with contextual intelligence, assigns a risk score, and generates daily threat reports.  
Built entirely with Python and GitHub Actions.

## 1. Overview

Security teams receive thousands of raw IOCs daily from different threat‑intelligence feeds. These feeds are inconsistent, duplicated, and difficult to prioritize.

This project solves that problem by:

- Aggregating multiple threat feeds (URLhaus, ThreatFox)
- Normalizing all IOCs into a unified schema
- Enriching indicators with geo, ASN, and reputation signals
- Scoring each IOC based on threat severity and context
- Producing daily high‑risk IOC reports
- Automating the entire pipeline using GitHub Actions

## 3. Data Sources

### URLhaus  
- Malicious URLs  
- CSV format  
- https://urlhaus.abuse.ch/downloads/csv/

### ThreatFox  
- IPs, domains, URLs, file hashes  
- JSON format  
- https://threatfox.abuse.ch/export/json/




