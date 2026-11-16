import json
import uuid
from mitmproxy import http
from sanitizer_engine import HybridSanitizer


class DLPProxyAddon:
    def __init__(self):
        self.sanitizer = HybridSanitizer()

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.method != "POST" or not flow.request.path.endswith("/chat/completions"):
            return

        try:
            payload = json.loads(flow.request.get_text())
        except json.JSONDecodeError:
            return

        request_id = str(uuid.uuid4())[:8]
        result = self.sanitizer.sanitize_openai_payload(payload, request_id)

        # 1. Política de bloqueo para datos críticos (SECRET / CREDIT_CARD)
        if result["action"] == "BLOCK":
            motivos = ", ".join(result["blocked_types"])
            print(f"[DLP-BLOCK] Petición {request_id} bloqueada por contener: {motivos}")
            error_body = {
                "error": {
                    "message": f"Bloqueado por política DLP corporativa. Datos críticos detectados: {motivos}",
                    "type": "dlp_policy_violation",
                    "code": "sensitive_data_blocked",
                }
            }
            flow.response = http.Response.make(
                403,
                json.dumps(error_body, ensure_ascii=False),
                {"Content-Type": "application/json"},
            )
            return

        # 2. Guardar mapa inverso en el flujo para rehidratar cuando vuelva la respuesta
        flow.metadata["dlp_tag_map"] = result["tag_to_value"]
        flow.metadata["dlp_request_id"] = request_id

        # 3. Reemplazar el body saliente con el texto sanitizado
        flow.request.text = json.dumps(result["sanitized_payload"], ensure_ascii=False)
        print(f"[DLP-ALLOW] Petición {request_id} sanitizada y reenviada.")

    def response(self, flow: http.HTTPFlow) -> None:
        tag_map = flow.metadata.get("dlp_tag_map")
        if not tag_map or not flow.response:
            return

        try:
            resp_data = json.loads(flow.response.get_text())
        except json.JSONDecodeError:
            return

        # Ordenar etiquetas por longitud descendente ([ID_10] antes que [ID_1])
        sorted_tags = sorted(tag_map.items(), key=lambda item: len(item[0]), reverse=True)

        modified = False
        for choice in resp_data.get("choices", []):
            msg = choice.get("message", {})
            content = msg.get("content")
            if isinstance(content, str):
                for tag, original_value in sorted_tags:
                    if tag in content:
                        content = content.replace(tag, original_value)
                        modified = True
                msg["content"] = content

        if modified:
            flow.response.text = json.dumps(resp_data, ensure_ascii=False)
            req_id = flow.metadata.get("dlp_request_id", "unknown")
            print(f"[DLP-REHYDRATE] Respuesta {req_id} rehidratada para el usuario interno.")


addons = [DLPProxyAddon()]