import json
from datetime import datetime, timezone
from typing import Dict

LOG_FILE = "audit_log.jsonl"


def log_sanitization_event(
    type_counts: Dict[str, int],
    latency_ms: float,
    request_id: str,
    action: str = "ALLOW",
) -> None:
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "action": action,
        "total_redactions": sum(type_counts.values()),
        "entities_detected": type_counts,
        "dlp_latency_ms": round(latency_ms, 2),
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")