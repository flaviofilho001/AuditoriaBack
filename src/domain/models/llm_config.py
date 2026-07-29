from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class LLMProviderType(str, Enum):
    GEMINI = "gemini"
    OLLAMA = "ollama"


class LLMConfig(BaseModel):
    provider: LLMProviderType = LLMProviderType.GEMINI
    # Para Gemini:
    api_key: Optional[str] = None
    gemini_model: str = "gemini-3.5-flash"  # Fixo no modelo gemini-3.5-flash
    max_requests_per_minute: int = 14  # Limite estrito de 14 RPM
    
    # Para Ollama:
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "gemma:2b"  # gemma:2b, gemma:12b, gemma:26b, qwen3.5:2b, etc.
    
    temperature: float = 0.2
    max_tokens: int = 2048
