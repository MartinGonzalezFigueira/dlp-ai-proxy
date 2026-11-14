import json
import uuid
from mitmproxy import http, ctx
from sanitizer_engine import HybridSanitizer

sanitizer = HybridSanitizer()


def request(flow: http.HTTPFlow) -> None:
    if flow.request.method == "POST" and "/chat/completions" in flow.request.path:
        raw_body = flow.request.get_text(strict=False)
        if not raw_body:
            return

        try:
            payload = json.loads(raw_body)
            req_id = str(uuid.uuid4())[:8]
            sanitized = sanitizer.sanitize_openai_payload(payload, request_id=req_id)
            flow.request.text = json.dumps(sanitized, ensure_ascii=False)
            ctx.log.info(f"[DLP-PROXY] Request {req_id} sanitizada y reenviada.")
        except json.JSONDecodeError:
            ctx.log.warn("[DLP-PROXY] Payload no es JSON válido.")