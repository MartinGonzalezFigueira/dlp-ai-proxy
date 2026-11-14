import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

AUDIT_FILE = Path("audit_log.jsonl")


def log_sanitization_event(
    entity_counts: Dict[str, int],
    latency_ms: float,
    request_id: str,
) -> None:
    """Guarda métricas de la intervención sin registrar los valores sensibles."""
    total = sum(entity_counts.values())
    if total == 0:
        return

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "detected_types": entity_counts,
        "total_replacements": total,
        "latency_ms": round(latency_ms, 2),
    }

    with AUDIT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")