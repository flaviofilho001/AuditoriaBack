import asyncio
import time
import structlog
from typing import Dict, Any, Optional, List

try:
    from google import genai
    from google.genai import types
    GENAI_SDK_AVAILABLE = True
except ImportError:
    GENAI_SDK_AVAILABLE = False

import httpx
from src.application.interfaces.illm_provider import ILLMProvider
from src.domain.models.llm_config import LLMConfig

logger = structlog.get_logger()


class GeminiRateLimitedProvider(ILLMProvider):
    """
    Provedor Google Gemini com o SDK oficial 'google-genai' e modelo 'gemini-3.5-flash'.
    Implementa Rate Limiting estrito de 14 RPM com throttling via asyncio.
    """

    def __init__(self, config: LLMConfig):
        self.config = config
        self.api_key = config.api_key
        self.model = "gemini-3.5-flash"
        self.max_rpm = min(config.max_requests_per_minute, 14)
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

    async def generate_completion(
        self, 
        prompt: str, 
        system_instruction: Optional[str] = None
    ) -> str:
        if not self.api_key:
            raise ValueError(
                "Chave de API do Gemini não configurada! Por favor insira a sua Gemini API Key na interface ou defina a variável GEMINI_API_KEY no Railway."
            )

        await self._enforce_rate_limit()

        # Executa a chamada do SDK google-genai de forma assíncrona
        def _call_sdk():
            client = genai.Client(api_key=self.api_key)
            
            # Tenta usar a nova API de interactions ou models.generate_content do SDK google-genai
            if hasattr(client, "interactions"):
                try:
                    interaction = client.interactions.create(
                        model=self.model,
                        input=f"{f'System: {system_instruction}' if system_instruction else ''}\nUser: {prompt}"
                    )
                    return interaction.output_text
                except Exception as e:
                    logger.warning("gemini_interactions_fallback", error=str(e))
            
            # Utiliza client.models.generate_content
            config_kwargs = {}
            if system_instruction:
                config_kwargs["system_instruction"] = system_instruction
            if self.config.temperature:
                config_kwargs["temperature"] = self.config.temperature

            response = client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=types.GenerateContentConfig(**config_kwargs) if config_kwargs else None
            )
            return response.text

        try:
            if GENAI_SDK_AVAILABLE:
                return await asyncio.to_thread(_call_sdk)
            else:
                # Fallback REST API via httpx caso o SDK não esteja instalado no ambiente
                return await self._call_rest_api(prompt, system_instruction)
        except Exception as e:
            logger.error("gemini_sdk_error", error=str(e))
            # Se der erro no modelo gemini-3.5-flash ou no SDK, tenta chamada REST fallback
            return await self._call_rest_api(prompt, system_instruction)

    async def _call_rest_api(self, prompt: str, system_instruction: Optional[str] = None) -> str:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"

        contents = []
        if system_instruction:
            contents.append({
                "role": "user",
                "parts": [{"text": f"Instrução do Sistema: {system_instruction}"}]
            })
            contents.append({
                "role": "model",
                "parts": [{"text": "Entendido."}]
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

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(url, json=payload)
            if response.status_code != 200:
                # Tenta fallback REST com gemini-1.5-flash se gemini-3.5-flash falhar no endpoint REST antigo
                fallback_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.api_key}"
                response = await client.post(fallback_url, json=payload)

            response.raise_for_status()
            data = response.json()
            candidates = data.get("candidates", [])
            if not candidates:
                return ""
            parts = candidates[0].get("content", {}).get("parts", [])
            return "".join([part.get("text", "") for part in parts])

    async def check_health(self) -> Dict[str, Any]:
        if not self.api_key:
            return {"status": "unconfigured", "provider": "gemini", "message": "Por favor informe a Gemini API Key"}
        
        try:
            res = await self.generate_completion("Responda 'OK'", system_instruction="Verificação")
            return {
                "status": "healthy",
                "provider": "gemini",
                "model": self.model,
                "max_rpm": self.max_rpm,
                "response_sample": res.strip()
            }
        except Exception as e:
            return {"status": "error", "provider": "gemini", "error": str(e)}
