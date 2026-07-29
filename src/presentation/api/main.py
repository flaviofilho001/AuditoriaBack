import os
import shutil
import tempfile
import zipfile
import subprocess
import structlog
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import httpx

from src import __version__
from src.domain.models.llm_config import LLMConfig, LLMProviderType
from src.infrastructure.ai.llm_factory import LLMFactory
from src.infrastructure.knowledge_base.grc_repository import GRCKnowledgeRepository
from src.application.use_cases.audit_use_case import AuditComplianceUseCase
from src.infrastructure.exporters.sarif_exporter import SarifReporter
from src.infrastructure.exporters.markdown_exporter import MarkdownPRReporter
from src.infrastructure.exporters.html_exporter import HTMLExecutiveReporter

logger = structlog.get_logger()

app = FastAPI(
    title="Auditor de Conformidade de APIs - Backend",
    description="API REST Clean Architecture para Auditoria Estática, GraphRAG e Análise de Conformidade GRC (OWASP Top 10, LGPD, ISO 27001).",
    version=__version__,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

grc_repo = GRCKnowledgeRepository()
audit_use_case = AuditComplianceUseCase(grc_repo)


class GitScanRequest(BaseModel):
    git_url: str
    branch: Optional[str] = "main"
    access_token: Optional[str] = None
    provider: LLMProviderType = LLMProviderType.GEMINI
    api_key: Optional[str] = None
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "gemma:2b"
    use_ai: bool = True


class ReportExportRequest(BaseModel):
    scan_result: Dict[str, Any]
    format: str = "html"


class LLMTestRequest(BaseModel):
    provider: LLMProviderType = LLMProviderType.GEMINI
    api_key: Optional[str] = None
    gemini_model: str = "gemini-3.5-flash"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "gemma:2b"
    prompt: str = "Resuma a importância do Artigo 46 da LGPD em 2 frases."


class OllamaModelsProxyRequest(BaseModel):
    ollama_base_url: str


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
    return {"documents": grc_repo.list_available_docs()}


@app.get("/api/v1/grc/docs/{doc_name}", tags=["GRC Knowledge Base"])
async def get_grc_doc(doc_name: str):
    content = grc_repo.get_document(doc_name)
    if not content:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Documento '{doc_name}' não encontrado na base GRC."
        )
    return {"document": doc_name, "content": content}


@app.post("/api/v1/scan/upload-zip", tags=["Audit Scanner"])
async def scan_upload_zip(
    file: UploadFile = File(...),
    provider: LLMProviderType = Form(LLMProviderType.GEMINI),
    api_key: Optional[str] = Form(None),
    ollama_base_url: str = Form("http://localhost:11434"),
    ollama_model: str = Form("gemma:2b"),
    use_ai: bool = Form(True)
):
    if not file.filename.endswith(".zip"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Por favor envie um arquivo com extensão .zip"
        )

    with tempfile.TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, "uploaded_project.zip")
        extract_path = os.path.join(temp_dir, "extracted")
        os.makedirs(extract_path, exist_ok=True)

        with open(zip_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        try:
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(extract_path)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Não foi possível descompactar o arquivo ZIP: {str(e)}"
            )

        resolved_key = api_key or os.getenv("GEMINI_API_KEY")
        llm_config = LLMConfig(
            provider=provider,
            api_key=resolved_key,
            gemini_model="gemini-3.5-flash",
            ollama_base_url=ollama_base_url,
            ollama_model=ollama_model
        )

        result = await audit_use_case.execute_audit(
            target_dir=extract_path,
            llm_config=llm_config,
            use_ai_enhancement=use_ai
        )

        return result


@app.post("/api/v1/scan/git-url", tags=["Audit Scanner"])
async def scan_git_url(request: GitScanRequest):
    git_url = request.git_url.strip()
    if request.access_token and "github.com" in git_url and "@" not in git_url:
        git_url = git_url.replace("https://", f"https://x-access-token:{request.access_token}@")

    with tempfile.TemporaryDirectory() as temp_dir:
        clone_path = os.path.join(temp_dir, "repo")

        try:
            cmd = ["git", "clone", "--depth", "1"]
            if request.branch:
                cmd.extend(["-b", request.branch])
            cmd.extend([git_url, clone_path])

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if proc.returncode != 0:
                logger.error("git_clone_failed", stderr=proc.stderr)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Falha ao clonar o repositório Git: {proc.stderr[:200]}"
                )
        except subprocess.TimeoutExpired:
            raise HTTPException(
                status_code=status.HTTP_408_REQUEST_TIMEOUT,
                detail="Tempo limite excedido ao clonar o repositório Git."
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Erro ao clonar repositório: {str(e)}"
            )

        resolved_key = request.api_key or os.getenv("GEMINI_API_KEY")
        llm_config = LLMConfig(
            provider=request.provider,
            api_key=resolved_key,
            gemini_model="gemini-3.5-flash",
            ollama_base_url=request.ollama_base_url,
            ollama_model=request.ollama_model
        )

        result = await audit_use_case.execute_audit(
            target_dir=clone_path,
            llm_config=llm_config,
            use_ai_enhancement=request.use_ai
        )

        return result


@app.post("/api/v1/report/export", tags=["Report Exporter"])
async def export_report(request: ReportExportRequest):
    fmt = request.format.lower()
    scan_result = request.scan_result

    if fmt == "html":
        content = HTMLExecutiveReporter.generate_html(scan_result)
        return Response(content=content, media_type="text/html")
    elif fmt in ["markdown", "md"]:
        content = MarkdownPRReporter.generate_markdown(scan_result)
        return Response(content=content, media_type="text/markdown")
    elif fmt == "sarif":
        content = SarifReporter.generate_sarif(scan_result)
        return content
    elif fmt == "graphml":
        graphml_content = scan_result.get("graphml_data", "")
        if not graphml_content:
            raise HTTPException(status_code=400, detail="Nenhum dado GraphML encontrado no resultado.")
        return Response(content=graphml_content, media_type="application/xml")
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Formato de exportação '{fmt}' não suportado. Use 'html', 'markdown', 'sarif' ou 'graphml'."
        )

# ==============================================================================
# FASE 4: GitHub PR Webhook
# ==============================================================================
from fastapi import BackgroundTasks, Request

async def process_github_pr_webhook(payload: Dict[str, Any]):
    """Processa o PR em background para não dar timeout no GitHub"""
    try:
        action = payload.get("action")
        if action not in ["opened", "synchronize", "reopened"]:
            return
            
        pr = payload.get("pull_request", {})
        repo = payload.get("repository", {})
        
        pr_number = pr.get("number")
        repo_full_name = repo.get("full_name")
        branch_name = pr.get("head", {}).get("ref", "main")
        clone_url = repo.get("clone_url")
        comments_url = pr.get("comments_url")
        
        if not clone_url or not comments_url:
            return

        logger.info("webhook_pr_started", repo=repo_full_name, pr=pr_number)

        # 1. Executa Auditoria via Clone
        llm_config = LLMConfig(provider=LLMProviderType.GEMINI, api_key=os.getenv("GEMINI_API_KEY"), gemini_model="gemini-3.5-flash")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            clone_path = os.path.join(temp_dir, "repo")
            cmd = ["git", "clone", "--depth", "1", "-b", branch_name, clone_url, clone_path]
            subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            result = await audit_use_case.execute_audit(target_dir=clone_path, llm_config=llm_config)
            
        # 2. Gera Comentário PR Markdown
        md_report = MarkdownPRReporter.generate_markdown(result)
        
        # 3. Posta no GitHub (Exige GITHUB_TOKEN configurado no Railway)
        github_token = os.getenv("GITHUB_TOKEN")
        if not github_token:
            logger.error("webhook_pr_failed", reason="GITHUB_TOKEN não configurado no servidor")
            return
            
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        async with httpx.AsyncClient() as client:
            res = await client.post(comments_url, json={"body": md_report}, headers=headers)
            res.raise_for_status()
            
        logger.info("webhook_pr_comment_posted", repo=repo_full_name, pr=pr_number)
        
    except Exception as e:
        logger.error("webhook_pr_error", error=str(e))

@app.post("/api/v1/webhooks/github", tags=["Webhooks"])
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Endpoint para receber eventos de Webhook do GitHub App (Fase 4).
    Requer configuração do webhook apontando para cá no repositório.
    """
    event = request.headers.get("X-GitHub-Event")
    if event == "pull_request":
        payload = await request.json()
        background_tasks.add_task(process_github_pr_webhook, payload)
        return {"status": "accepted", "message": "Pull request audit started in background"}
    return {"status": "ignored", "event": event}


@app.post("/api/v1/llm/test", tags=["LLM Provider"])
async def test_llm_provider(request: LLMTestRequest):
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
            return {"success": False, "health": health, "response": None}

        system_instruction = "Você é um auditor especialista em Segurança Cibernética, OWASP Top 10 e LGPD."
        response_text = await provider_inst.generate_completion(
            prompt=request.prompt,
            system_instruction=system_instruction
        )

        return {"success": True, "health": health, "response": response_text}
    except Exception as e:
        logger.error("llm_test_endpoint_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Falha ao comunicar com o provedor LLM ({request.provider}): {str(e)}"
        )


@app.post("/api/v1/llm/ollama/models", tags=["LLM Provider Proxy"])
async def list_ollama_models(request: OllamaModelsProxyRequest):
    """
    Endpoint Proxy para buscar modelos do Ollama.
    Resolve problemas de CORS/Mixed Content permitindo que o Backend busque as tags e retorne ao Frontend.
    """
    url = f"{request.ollama_base_url.rstrip('/')}/api/tags"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            res = await client.get(url)
            res.raise_for_status()
            data = res.json()
            models = [m.get("name") for m in data.get("models", [])]
            return {"success": True, "models": models}
    except httpx.RequestError as e:
        # Se for localhost e falhar, é porque está na nuvem e o Ollama não tá exposto pra internet via Ngrok
        if "localhost" in request.ollama_base_url or "127.0.0.1" in request.ollama_base_url:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="O Backend está na Nuvem e tentou acessar seu localhost, mas não encontrou o Ollama. Se quiser usar o backend na nuvem, você precisa usar o Ngrok na sua máquina."
            )
        raise HTTPException(status_code=400, detail=f"Erro de conexão com Ollama: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8080))
    uvicorn.run("src.presentation.api.main:app", host="0.0.0.0", port=port, reload=True)
