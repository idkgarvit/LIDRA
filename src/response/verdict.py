from enum import Enum
from typing import Dict, List, Optional


class Verdict(Enum):
    PASS = "pass"
    DROP = "drop"
    RATE_LIMIT = "rate_limit"
    LOG_ONLY = "log_only"


def decide_verdict(detections: List[Dict], ip_reputation: Optional[Dict] = None,
                   rate_info: Optional[Dict] = None) -> Verdict:
    for d in detections:
        severity = d.get("severity", "low")
        if severity in ("critical", "high"):
            return Verdict.DROP
        if severity == "medium":
            return Verdict.LOG_ONLY

    if ip_reputation:
        score = ip_reputation.get("threat_score", 0)
        if score >= 70:
            return Verdict.DROP
        if score >= 40:
            return Verdict.LOG_ONLY

    if rate_info:
        if rate_info.get("is_throttled"):
            return Verdict.RATE_LIMIT

    return Verdict.PASS
