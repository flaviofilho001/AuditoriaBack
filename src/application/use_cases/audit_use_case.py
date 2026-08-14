import structlog
from typing import List, Dict, Any, Optional

from src.domain.models.vulnerability import VulnerabilityFinding, Severity, GRCFramework
from src.domain.models.code_graph import CodeGraphSummary
from src.domain.models.llm_config import LLMConfig, LLMProviderType
from src.infrastructure.code_parsers.ast_scanner import ASTCodeScanner
from src.infrastructure.graph.graph_builder import NetworkXGraphBuilder
from src.infrastructure.knowledge_base.grc_repository import GRCKnowledgeRepository
from src.infrastructure.ai.llm_factory import LLMFactory

logger = structlog.get_logger()


class AuditComplianceUseCase:
    """Caso de uso principal para executar a Auditoria de Conformidade GRC (AST + GraphRAG + IA)."""

    def __init__(self, grc_repo: GRCKnowledgeRepository):
        self.scanner = ASTCodeScanner()
        self.graph_builder = NetworkXGraphBuilder()
        self.grc_repo = grc_repo

    async def execute_audit(
        self,
        target_dir: str,
        llm_config: Optional[LLMConfig] = None,
        use_ai_enhancement: bool = True
    ) -> Dict[str, Any]:
        logger.info("executing_compliance_audit", target_dir=target_dir, use_ai=use_ai_enhancement)

        # 1. Varredura Estática AST
        scan_result = self.scanner.scan_directory(target_dir)
        findings: List[VulnerabilityFinding] = scan_result["findings"]
        nodes = scan_result["nodes"]
        edges = scan_result["edges"]
        files_scanned = scan_result["files_scanned"]

        # 2. Construção do Grafo de Código (GraphRAG)
        graph_summary: CodeGraphSummary = self.graph_builder.build_graph(nodes, edges)

        # 3. Enriquecimento Opcional com IA (gemini-3.5-flash / Ollama)
        ai_summary = "Análise estática concluída."
        if use_ai_enhancement and llm_config:
            try:
                ai_summary = await self._run_ai_analysis(findings, graph_summary, llm_config)
            except Exception as e:
                logger.error("ai_enrichment_failed", error=str(e))
                ai_summary = f"Análise estática concluída com sucesso. (Nota: IA indisponível ou limitada: {e})"

        # 4. Agrupamento por Gravidade
        severity_counts = {
            "CRITICAL": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "HIGH": sum(1 for f in findings if f.severity == Severity.HIGH),
            "MEDIUM": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "LOW": sum(1 for f in findings if f.severity == Severity.LOW),
        }

        return {
            "summary": {
                "total_files_scanned": len(files_scanned),
                "total_findings": len(findings),
                "severity_counts": severity_counts,
                "graph_summary": graph_summary.model_dump(),
                "ai_executive_summary": ai_summary
            },
            "findings": [f.model_dump() for f in findings],
            "files_scanned": files_scanned,
            "graphml_data": self.graph_builder.export_to_graphml()
        }

    async def _run_ai_analysis(
        self, 
        findings: List[VulnerabilityFinding], 
        graph_summary: CodeGraphSummary,
        llm_config: LLMConfig
    ) -> str:
        if not findings:
            return "Nenhuma vulnerabilidade crítica ou falha de conformidade GRC foi identificada no repositório."

        provider_inst = LLMFactory.create_provider(llm_config)
        
        # Prepara resumo dos achados para a IA
        findings_summary_str = "\n".join([
            f"- [{f.severity}] {f.title} ({f.location.file_path}:{f.location.line_start}) - GRC: {[g.control_id for g in f.grc_mappings]}"
            for f in findings[:8]  # Limita aos 8 principais para economizar tokens
        ])

        grc_context = self.grc_repo.get_relevant_context(["lgpd", "owasp", "autorizacao", "segredo", "excecoes", "publica"])

        prompt = f"""
Você é um Auditor Sênior de Conformidade GRC e Segurança de APIs.
Analise os seguintes achados de código extraídos do projeto:

ACHADOS ENCONTRADOS:
{findings_summary_str}

RESUMO DO GRAFO DE CÓDIGO:
Total de nós: {graph_summary.total_nodes}, Endpoints: {graph_summary.endpoints_count}

CONTEXTO DE NORMAS GRC E EXCEÇÕES:
{grc_context[:1200]}

DIRETRIZES DE SANIDADE E VALIDAÇÃO DE ROTAS PÚBLICAS:
- Valide se os achados referem-se a rotas públicas legítimas de entrada (como Login, Cadastro/Register, Recuperação de Senha ou Healthcheck).
- Se a rota for de Login ou Cadastro, reconheça que a ausência de autorização [Authorize] prévia é necessária e esperada para permitir o acesso do visitante.
- Jamais afirme que formulários de Login/Cadastro em si permitem "alteração não autorizada de perfis de terceiros" ou "extração de dados de terceiros" a menos que o código exponha explicitamente dados confidenciais de outros usuários.

TAREFA:
Elabore um Resumo Executivo em 3 parágrafos concisos em português:
1. Avaliação geral do nível de risco da aplicação em relação a OWASP Top 10 e LGPD Art. 46.
2. Os 2 pontos mais críticos a serem corrigidos imediatamente (focando em vulnerabilidades reais).
3. Recomendação final de remediação para o time de desenvolvimento.
"""
        system_instruction = "Você é um auditor rigoroso e tecnicamente preciso de conformidade GRC. Valide o contexto de rotas públicas e responda em português claro e objetivo."
        
        return await provider_inst.generate_completion(prompt, system_instruction=system_instruction)
