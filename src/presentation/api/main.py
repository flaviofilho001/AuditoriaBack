import os
import structlog
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

from src import __version__
from src.domain.models.llm_config import LLMConfig, LLMProviderType
from src.infrastructure.ai.llm_factory import LLMFactory
from src.infrastructure.knowledge_base.grc_repository import GRCKnowledgeRepository

logger = structlog.get_logger()

app = FastAPI(
    title="Auditor de Conformidade de APIs - Backend",
    description="API REST Clean Architecture para Auditoria Estática, GraphRAG e Análise de Conformidade GRC (OWASP Top 10, LGPD, ISO 27001).",
    version=__version__,
)

# Configuração de CORS para permitir acesso irrestrito do Frontend (Railway / Localhost)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Instância global do repositório GRC
grc_repo = GRCKnowledgeRepository()


class LLMTestRequest(BaseModel):
    provider: LLMProviderType = LLMProviderType.GEMINI
    api_key: Optional[str] = None
    gemini_model: str = "gemini-3.5-flash"  # Exclusivo gemini-3.5-flash
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "gemma:2b"
    prompt: str = "Resuma a importância do Artigo 46 da LGPD em 2 frases."


@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "healthy",
        "service": "AuditoriaBack",
        "version": __version__,
        "grc_docs_count": len(grc_repo.list_available_docs())
    }


@app.get("/api/v1/grc/docs", tags=["GRC Knowledge Base"])
async def list_grc_docs():
    """Lista todos os documentos de GRC carregados na base de conhecimento."""
    return {
        "documents": grc_repo.list_available_docs()
    }


@app.get("/api/v1/grc/docs/{doc_name}", tags=["GRC Knowledge Base"])
async def get_grc_doc(doc_name: str):
    """Obtém o conteúdo completo de um documento GRC (ex: LGPD, OWASP_TOP_10_2021)."""
    content = grc_repo.get_document(doc_name)
    if not content:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Documento '{doc_name}' não encontrado na base GRC."
        )
    return {"document": doc_name, "content": content}


@app.post("/api/v1/llm/test", tags=["LLM Provider"])
async def test_llm_provider(request: LLMTestRequest):
    """Testa a conexão e resposta do provedor de LLM (Gemini gemini-3.5-flash com Rate Limiter de 14 RPM ou Ollama Local)."""
    api_key = request.api_key or os.getenv("GEMINI_API_KEY")
    
    config = LLMConfig(
        provider=request.provider,
        api_key=api_key,
        gemini_model="gemini-3.5-flash",
        ollama_base_url=request.ollama_base_url,
        ollama_model=request.ollama_model
    )

    try:
        provider_inst = LLMFactory.create_provider(config)
        health = await provider_inst.check_health()
        
        if health.get("status") in ["unconfigured", "unreachable"]:
            return {
                "success": False,
                "health": health,
                "response": None
            }

        system_instruction = "Você é um auditor especialista em Segurança Cibernética, OWASP Top 10 e LGPD."
        response_text = await provider_inst.generate_completion(
            prompt=request.prompt,
            system_instruction=system_instruction
        )

        return {
            "success": True,
            "health": health,
            "response": response_text
        }
    except Exception as e:
        logger.error("llm_test_endpoint_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Falha ao comunicar com o provedor LLM ({request.provider}): {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8080))
    uvicorn.run("src.presentation.api.main:app", host="0.0.0.0", port=port, reload=True)
