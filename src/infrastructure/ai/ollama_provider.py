import structlog
import httpx
from typing import Dict, Any, Optional, List
from src.application.interfaces.illm_provider import ILLMProvider
from src.domain.models.llm_config import LLMConfig

logger = structlog.get_logger()


class OllamaProvider(ILLMProvider):
    """
    Provedor Ollama.
    Suporta servidores Ollama locais ou expostos via Ngrok / Cloudflare Tunnel.
    """

    def __init__(self, config: LLMConfig):
        self.config = config
        self.base_url = config.ollama_base_url.rstrip("/")
        self.model = config.ollama_model or "gemma:2b"

    async def generate_completion(
        self, 
        prompt: str, 
        system_instruction: Optional[str] = None
    ) -> str:
        url = f"{self.base_url}/api/generate"

        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system_instruction or "",
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens
            }
        }

        async with httpx.AsyncClient(timeout=120.0) as client:
            try:
                response = await client.post(url, json=payload)
                if response.status_code != 200:
                    logger.error("ollama_api_error", status_code=response.status_code, response=response.text)
                    response.raise_for_status()

                data = response.json()
                return data.get("response", "")
            except httpx.ConnectError:
                logger.error("ollama_connection_failed", base_url=self.base_url)
                if "localhost" in self.base_url or "127.0.0.1" in self.base_url:
                    raise RuntimeError(
                        f"Não foi possível conectar ao Ollama em {self.base_url}. Como o backend está rodando no Railway (Nuvem), para conectar ao Ollama da sua máquina exponha a porta com Ngrok ('ngrok http 11434') e insira a URL pública no campo 'Ollama Base URL', ou use a chave do Google Gemini."
                    )
                else:
                    raise RuntimeError(
                        f"Não foi possível conectar ao servidor Ollama em {self.base_url}. Verifique se o endereço está correto e online."
                    )

    async def check_health(self) -> Dict[str, Any]:
        url = f"{self.base_url}/api/tags"
        async with httpx.AsyncClient(timeout=5.0) as client:
            try:
                response = await client.get(url)
                if response.status_code == 200:
                    models_data = response.json()
                    models_list: List[str] = [m.get("name") for m in models_data.get("models", [])]
                    is_model_available = any(self.model in m for m in models_list)
                    return {
                        "status": "healthy" if is_model_available else "model_missing",
                        "provider": "ollama",
                        "base_url": self.base_url,
                        "current_model": self.model,
                        "available_models": models_list,
                        "message": "Modelo disponível" if is_model_available else f"Modelo '{self.model}' não encontrado. Execute 'ollama pull {self.model}'."
                    }
            except Exception as e:
                return {
                    "status": "unreachable",
                    "provider": "ollama",
                    "base_url": self.base_url,
                    "error": str(e),
                    "message": "Ollama inacessível a partir do servidor em nuvem."
                }
        return {"status": "unknown"}
