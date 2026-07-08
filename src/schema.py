from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from datetime import datetime

class IOC(BaseModel):
    indicator_type: str = Field(..., description="Type of IOC: ip, domain, url, hash")
    indicator_value: str = Field(..., description="The actual IOC value")
    source_feed: str = Field(..., description="Feed where the IOC was collected from")
    threat_type: Optional[str] = Field(None, description="Threat category: malware, phishing, botnet, etc.")
    first_seen: Optional[datetime] = Field(None, description="Earliest date the IOC appeared")
    last_seen: Optional[datetime] = Field(None, description="Most recent date the IOC appeared")
    confidence: Optional[float] = Field(None, description="Confidence score from feed, if available")
    tags: Optional[List[str]] = Field(default_factory=list, description="Additional labels or metadata")
    enrichment: Optional[Dict] = Field(default_factory=dict, description="Geo, ASN, reputation, etc.")
    risk_score: Optional[float] = Field(None, description="Final computed risk score")
