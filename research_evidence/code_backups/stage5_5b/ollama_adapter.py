"""Local-only Ollama interface, stdlib-only. Does not contact hosted APIs."""
from __future__ import annotations
import json
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError


class LocalModelError(RuntimeError):
    pass


class OllamaAgent:
    def __init__(self, model_name: str, base_url: str = "http://127.0.0.1:11434", timeout: int = 90,
                 temperature: float = 0.0, num_predict: int = 256):
        p = urlparse(base_url)
        if p.scheme != "http" or p.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Only a local HTTP Ollama endpoint is allowed")
        if not model_name or not model_name.strip():
            raise ValueError("Model name is required")
        self.model_name = model_name
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.temperature = temperature
        self.num_predict = num_predict
        self.model_digest = "unavailable"

    def _request(self, path: str, payload: dict | None = None) -> dict:
        url = self.base_url + path
        encoded = None if payload is None else json.dumps(payload).encode("utf-8")
        req = Request(url, data=encoded, headers={"Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (OSError, URLError, ValueError) as exc:
            raise LocalModelError(f"Ollama unavailable or returned invalid data: {exc}") from exc
        if not isinstance(data, dict):
            raise LocalModelError("Ollama returned non-object JSON")
        return data

    def check_model(self) -> str:
        tags = self._request("/api/tags").get("models", [])
        for item in tags:
            if item.get("name") == self.model_name or item.get("model") == self.model_name:
                self.model_digest = item.get("digest", "unavailable")
                return self.model_digest
        raise LocalModelError(
            f"Model '{self.model_name}' not installed locally. Run `ollama pull {self.model_name}` first.")

    def next_message(self, messages: list[dict[str, str]], seed: int) -> str:
        payload = {
            "model": self.model_name, "stream": False, "format": "json", "messages": messages,
            "options": {"temperature": self.temperature, "seed": int(seed),
                        "num_predict": self.num_predict}
        }
        data = self._request("/api/chat", payload)
        output = data.get("message", {}).get("content")
        if not isinstance(output, str):
            raise LocalModelError("Ollama response omitted message.content")
        return output
