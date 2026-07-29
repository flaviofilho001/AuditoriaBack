import asyncio
import time
import structlog
import httpx
from typing import Dict, Any, Optional, List
from src.application.interfaces.illm_provider import ILLMProvider
from src.domain.models.llm_config import LLMConfig

logger = structlog.get_logger()


class GeminiRateLimitedProvider(ILLMProvider):
    """
    Provedor Google Gemini com Rate Limiting Estrito (Máximo 14 requisições por minuto).
    Utiliza gemini-1.5-flash por padrão com suporte a modelos oficiais da Google AI.
    """

    def __init__(self, config: LLMConfig):
        self.config = config
        self.api_key = config.api_key
        # Se for especificado um modelo inválido, faz fallback para o modelo oficial 'gemini-1.5-flash'
        self.model = config.gemini_model if config.gemini_model and "3.5" not in config.gemini_model else "gemini-1.5-flash"
        self.max_rpm = min(config.max_requests_per_minute, 14)  # Força máximo de 14 RPM
        self._request_timestamps: List[float] = []
        self._lock = asyncio.Lock()

    async def _enforce_rate_limit(self):
        async with self._lock:
            now = time.time()
            self._request_timestamps = [t for t in self._request_timestamps if now - t < 60.0]

            if len(self._request_timestamps) >= self.max_rpm:
                oldest_in_window = self._request_timestamps[0]
                wait_time = 60.0 - (now - oldest_in_window) + 0.5
                logger.info(
                    "gemini_rate_limit_throttling",
                    requests_in_window=len(self._request_timestamps),
                    wait_seconds=round(wait_time, 2)
                )
                await asyncio.sleep(max(wait_time, 0.1))
                now = time.time()
                self._request_timestamps = [t for t in self._request_timestamps if now - t < 60.0]

            self._request_timestamps.append(now)

    async def _make_api_call(self, model_name: str, payload: dict) -> httpx.Response:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={self.api_key}"
        async with httpx.AsyncClient(timeout=60.0) as client:
            return await client.post(url, json=payload)

    async def generate_completion(
        self, 
        prompt: str, 
        system_instruction: Optional[str] = None
    ) -> str:
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY não foi configurada. Preencha a chave na interface ou configure a variável GEMINI_API_KEY no Railway.")

        await self._enforce_rate_limit()

        contents = []
        if system_instruction:
            contents.append({
                "role": "user",
                "parts": [{"text": f"Instrução do Sistema: {system_instruction}"}]
            })
            contents.append({
                "role": "model",
                "parts": [{"text": "Entendido. Seguirei rigorosamente as instruções do sistema."}]
            })
        
        contents.append({
            "role": "user",
            "parts": [{"text": prompt}]
        })

        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": self.config.temperature,
                "maxOutputTokens": self.config.max_tokens
            }
        }

        # Tenta a chamada no modelo configurado
        response = await self._make_api_call(self.model, payload)
        
        # Se retornar erro 503 ou 404 por nome de modelo inválido, tenta fallback para gemini-1.5-flash
        if response.status_code in [404, 503] and self.model != "gemini-1.5-flash":
            logger.warning("gemini_model_fallback_triggered", original_model=self.model, status_code=response.status_code)
            response = await self._make_api_call("gemini-1.5-flash", payload)

        if response.status_code != 200:
            logger.error("gemini_api_error", status_code=response.status_code, response=response.text)
            response.raise_for_status()
        
        data = response.json()
        try:
            candidates = data.get("candidates", [])
            if not candidates:
                return ""
            parts = candidates[0].get("content", {}).get("parts", [])
            return "".join([part.get("text", "") for part in parts])
        except Exception as e:
            logger.error("gemini_parse_error", error=str(e), raw_response=data)
            raise RuntimeError(f"Erro ao parsear resposta do Gemini: {e}")

    async def check_health(self) -> Dict[str, Any]:
        if not self.api_key:
            return {"status": "unconfigured", "provider": "gemini", "message": "API Key ausente"}
        
        try:
            res = await self.generate_completion("Responda apenas 'OK'", system_instruction="Verificação de saúde")
            return {
                "status": "healthy",
                "provider": "gemini",
                "model": self.model,
                "max_rpm": self.max_rpm,
                "response_sample": res.strip()
            }
        except Exception as e:
            return {"status": "error", "provider": "gemini", "error": str(e)}
