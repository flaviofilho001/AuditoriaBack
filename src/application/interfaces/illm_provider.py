from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class ILLMProvider(ABC):
    """Interface abstrata para provedores de LLM (Gemini com Rate Limit e Ollama local)"""

    @abstractmethod
    async def generate_completion(
        self, 
        prompt: str, 
        system_instruction: Optional[str] = None
    ) -> str:
        """Gera uma conclusão com base no prompt fornecido."""
        pass

    @abstractmethod
    async def check_health(self) -> Dict[str, Any]:
        """Verifica a disponibilidade do provedor de LLM."""
        pass
