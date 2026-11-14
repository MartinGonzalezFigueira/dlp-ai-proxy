import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


class MockOpenAIHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length).decode("utf-8")
        payload = json.loads(raw_body)

        print("\n" + "=" * 55)
        print("🌐 [API IA EXTERNA] Payload recibido desde Internet:")
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        print("=" * 55)

        user_prompt = payload["messages"][-1]["content"]
        response_data = {
            "id": "chatcmpl-demo-001",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": payload.get("model", "gpt-4o-mini"),
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": f"Procesado con éxito por la IA externa. Texto recibido: {user_prompt}",
                    },
                    "finish_reason": "stop",
                }
            ],
        }

        resp_bytes = json.dumps(response_data, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_bytes)))
        self.end_headers()
        self.wfile.write(resp_bytes)

    def log_message(self, format, *args):
        pass  # Silenciar logs HTTP crudos para que se vea limpio el JSON


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 9000), MockOpenAIHandler)
    print("🟢 API de IA Externa (Mock) escuchando en http://127.0.0.1:9000 ...")
    server.serve_forever()