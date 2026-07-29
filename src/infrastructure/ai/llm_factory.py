from src.application.interfaces.illm_provider import ILLMProvider
from src.domain.models.llm_config import LLMConfig, LLMProviderType
from src.infrastructure.ai.gemini_provider import GeminiRateLimitedProvider
from src.infrastructure.ai.ollama_provider import OllamaProvider


class LLMFactory:
    """Fábrica para instanciar o provedor de LLM configurado (Gemini ou Ollama)"""

    @staticmethod
    def create_provider(config: LLMConfig) -> ILLMProvider:
        if config.provider == LLMProviderType.GEMINI:
            return GeminiRateLimitedProvider(config)
        elif config.provider == LLMProviderType.OLLAMA:
            return OllamaProvider(config)
        else:
            raise ValueError(f"Provedor LLM desconhecido: {config.provider}")
