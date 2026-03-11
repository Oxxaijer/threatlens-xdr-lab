from pydantic import BaseModel
from typing import Optional


class ThreatEvent(BaseModel):
    timestamp: str
    source_type: str
    event_type: str
    severity: str
    host: str
    source_ip: Optional[str] = None
    user: Optional[str] = None
    process_name: Optional[str] = None
    description: str
    raw_data: dict