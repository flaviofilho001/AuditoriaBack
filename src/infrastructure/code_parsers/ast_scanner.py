import re
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
import structlog

from src.domain.models.vulnerability import (
    VulnerabilityFinding, Severity, FileLocation, GRCMapping, GRCFramework
)
from src.domain.models.code_graph import GraphNode, GraphEdge, NodeKind, EdgeKind

logger = structlog.get_logger()

PII_KEYWORDS = [
    "cpf", "cnpj", "rg", "email", "senha", "password", "pass", "secret",
    "cartao", "credit_card", "cvv", "telefone", "phone", "biometria",
    "salario", "medical", "saude"
]

SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|secret|password|passwd|pwd|token|access[_-]?token)\s*[:=]\s*["\']([^"\'\s]{8,})["\']', "Segredo Hardcoded"),
    (r'(?i)(mongodb(\+srv)?|postgres|postgresql|mysql|sqlserver):\/\/[^\s"\'<>]+', "Connection String Insegura"),
    (r'AIzaSy[A-Za-z0-9_-]{33}', "Google API Key Hardcoded"),
    (r'sk-[A-Za-z0-9]{48}', "OpenAI Key Hardcoded"),
]


class ASTCodeScanner:
    """Scanner Estático Multi-Linguagem usando análise estrutural AST / Regex de alta precisão."""

    def __init__(self):
        pass

    def scan_directory(self, target_dir: str) -> Dict[str, Any]:
        """
        Varre todos os arquivos de um diretório descompactado ou clonado.
        Retorna os achados estáticos e elementos para a construção do Grafo de Código.
        """
        findings: List[VulnerabilityFinding] = []
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []
        files_scanned: List[str] = []

        root_path = Path(target_dir)
        if not root_path.exists():
            raise FileNotFoundError(f"Diretório não encontrado: {target_dir}")

        for file_path in root_path.rglob("*"):
            if file_path.is_file():
                # Ignora diretórios comuns de build / git
                rel_parts = file_path.relative_to(root_path).parts
                if any(ignored in rel_parts for ignored in [".git", "node_modules", "bin", "obj", ".venv", "__pycache__"]):
                    continue

                rel_str = str(file_path.relative_to(root_path)).replace("\\", "/")
                files_scanned.append(rel_str)

                # Nó do Arquivo no Grafo
                file_node_id = f"file::{rel_str}"
                nodes.append(GraphNode(
                    id=file_node_id,
                    label=file_path.name,
                    kind=NodeKind.FILE,
                    file_path=rel_str
                ))

                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    lines = content.split("\n")

                    # 1. Checagem de Segredos e Chaves Hardcoded
                    self._check_hardcoded_secrets(rel_str, lines, findings)

                    # 2. Parsing Específico por Extensão
                    ext = file_path.suffix.lower()
                    if ext in [".cs", ".go", ".py", ".java", ".ts", ".js"]:
                        self._scan_source_code(rel_str, ext, lines, file_node_id, findings, nodes, edges)
                    elif ext in [".json", ".yaml", ".yml", ".env"] or file_path.name.startswith("appsettings"):
                        self._scan_config_file(rel_str, lines, file_node_id, findings, nodes)

                except Exception as e:
                    logger.error("scan_file_error", file=rel_str, error=str(e))

        return {
            "findings": findings,
            "nodes": nodes,
            "edges": edges,
            "files_scanned": files_scanned
        }

    def _check_hardcoded_secrets(self, file_path: str, lines: List[str], findings: List[VulnerabilityFinding]):
        for idx, line in enumerate(lines, start=1):
            for pattern, label in SECRET_PATTERNS:
                match = re.search(pattern, line)
                if match:
                    findings.append(VulnerabilityFinding(
                        id=f"SECRET-{len(findings)+1:03d}",
                        rule_id="OWASP-A05-HARDCODED-SECRET",
                        title=f"{label} Encontrado no Código/Config",
                        severity=Severity.CRITICAL,
                        description=f"Identificada uma string contendo credencial/segredo sensível em texto claro.",
                        recommendation="Mova este segredo para variáveis de ambiente (.env) ou Key Vault (Azure Key Vault / HashiCorp Vault).",
                        location=FileLocation(
                            file_path=file_path,
                            line_start=idx,
                            snippet=line.strip()[:100]
                        ),
                        grc_mappings=[
                            GRCMapping(
                                framework=GRCFramework.OWASP_TOP_10,
                                control_id="A05:2021",
                                title="Security Misconfiguration",
                                description="Credenciais hardcoded no código expõem o ambiente a vazamento direto."
                            ),
                            GRCMapping(
                                framework=GRCFramework.ISO_27001,
                                control_id="A.8.9",
                                title="Gerenciamento de Configuração",
                                description="Segredos não devem ser mantidos em controle de versão."
                            )
                        ],
                        detected_by="ASTCodeScanner"
                    ))

    def _is_public_route_endpoint(self, file_path: str, line_idx: int, lines: List[str]) -> bool:
        """Verifica se o endpoint é por natureza ou anotação ([AllowAnonymous]) uma rota pública legítima."""
        start_idx = max(0, line_idx - 6)
        end_idx = min(len(lines), line_idx + 6)
        surrounding = "\n".join(lines[start_idx:end_idx]).lower()

        # 1. Atributos explícitos de isenção de autorização
        if any(attr in surrounding for attr in [
            "[allowanonymous]", "@allowanonymous", "@public", "@permitall", 
            "allowanonymous", "ispublic", "allowany"
        ]):
            return True

        # 2. Palavras-chave de rotas de autenticação/registro públicas
        if any(kw in surrounding for kw in ["login", "register", "signup", "signin", "forgotpassword", "resetpassword", "healthz", "swagger"]):
            return True

        # 3. Controllers conhecidos de Conta/Autenticação tratam rotas públicas de login/registro
        if any(kw in file_path.lower() for kw in ["auth", "account", "login", "register", "health"]):
            if any(kw in surrounding for kw in ["login", "register", "signup", "signin", "authenticate"]):
                return True

        return False

    def _scan_source_code(
        self, file_path: str, ext: str, lines: List[str], 
        file_node_id: str, findings: List[VulnerabilityFinding], 
        nodes: List[GraphNode], edges: List[GraphEdge]
    ):
        has_auth_middleware = False
        in_controller = False

        for idx, line in enumerate(lines, start=1):
            line_str = line.strip()

            # Checa anotações de autorização (C#, Java, Python)
            if any(auth_kw in line_str for auth_kw in ["[Authorize]", "@PreAuthorize", "@login_required", "authMiddleware", "Bearer"]):
                has_auth_middleware = True

            # Identifica Controllers / Endpoints
            is_endpoint = False
            http_method = ""

            if ext == ".cs":
                if "[ApiController]" in line_str or "ControllerBase" in line_str:
                    in_controller = True
                if line_str.startswith("[Http") or line_str.startswith("[Route"):
                    is_endpoint = True
                    http_method = line_str
            elif ext == ".go":
                if any(m in line_str for m in [".GET(", ".POST(", ".PUT(", ".DELETE(", "http.HandleFunc("]):
                    is_endpoint = True
                    http_method = "Go HTTP Route"
            elif ext == ".py":
                if any(m in line_str for m in ["@app.get", "@app.post", "@app.put", "@app.delete", "@router.get", "@router.post"]):
                    is_endpoint = True
                    http_method = line_str
            elif ext in [".ts", ".js"]:
                if any(m in line_str for m in ["app.get(", "app.post(", "router.get(", "router.post("]):
                    is_endpoint = True
                    http_method = line_str

            if is_endpoint:
                is_public = self._is_public_route_endpoint(file_path, idx, lines)
                endpoint_node_id = f"endpoint::{file_path}::{idx}"
                nodes.append(GraphNode(
                    id=endpoint_node_id,
                    label=f"Endpoint ({http_method})",
                    kind=NodeKind.ENDPOINT,
                    file_path=file_path,
                    line_number=idx,
                    properties={"has_auth": has_auth_middleware, "is_public": is_public}
                ))
                edges.append(GraphEdge(
                    source_id=file_node_id,
                    target_id=endpoint_node_id,
                    kind=EdgeKind.EXPOSES_ROUTE
                ))

                # Se for um endpoint e não tiver auth no arquivo/linha nem for rota pública legítima -> Alerta
                if not has_auth_middleware and not is_public:
                    findings.append(VulnerabilityFinding(
                        id=f"AUTH-{len(findings)+1:03d}",
                        rule_id="OWASP-A01-NO-AUTH",
                        title="Endpoint Exposto Sem Autenticação/Autorização",
                        severity=Severity.HIGH,
                        description=f"O endpoint em {file_path}:{idx} não possui anotações de autorização explícitas ([Authorize], @login_required).",
                        recommendation="Exija autenticação obrigatória via JWT/OAuth2 ou anote o método explicitamente.",
                        location=FileLocation(
                            file_path=file_path,
                            line_start=idx,
                            snippet=line_str[:120]
                        ),
                        grc_mappings=[
                            GRCMapping(
                                framework=GRCFramework.OWASP_TOP_10,
                                control_id="A01:2021",
                                title="Broken Access Control",
                                description="Endpoints expostos sem verificação de identidade."
                            ),
                            GRCMapping(
                                framework=GRCFramework.LGPD,
                                control_id="Art. 46",
                                title="Segurança da Informação",
                                description="Medidas técnicas para evitar acessos não autorizados."
                            )
                        ],
                        detected_by="ASTCodeScanner"
                    ))

            # 3. Checagem de Vazamento de PII em Logs (LGPD Art. 46)
            if any(log_kw in line_str.lower() for log_kw in ["logger.", "log.", "console.log", "fmt.println", "system.out.println"]):
                for pii in PII_KEYWORDS:
                    if pii in line_str.lower():
                        findings.append(VulnerabilityFinding(
                            id=f"LGPD-LOG-{len(findings)+1:03d}",
                            rule_id="LGPD-PII-LOG-LEAK",
                            title=f"Registro de Log com Dado Pessoal Sensível ({pii.upper()})",
                            severity=Severity.HIGH,
                            description=f"O código está registrando o campo '{pii}' diretamente nos logs da aplicação.",
                            recommendation="Sanitize ou mascare o dado pessoal sensível (ex: ***.456.789-**) antes de enviar para o logger.",
                            location=FileLocation(
                                file_path=file_path,
                                line_start=idx,
                                snippet=line_str[:120]
                            ),
                            grc_mappings=[
                                GRCMapping(
                                    framework=GRCFramework.LGPD,
                                    control_id="Art. 46",
                                    title="Segurança dos Dados Pessoais",
                                    description="Vazamento de PII em arquivos de log sem mascaramento."
                                ),
                                GRCMapping(
                                    framework=GRCFramework.ISO_27001,
                                    control_id="A.8.15",
                                    title="Registros de Eventos (Logging)",
                                    description="Logs não devem conter dados sensíveis de usuários."
                                )
                            ],
                            detected_by="ASTCodeScanner"
                        ))
                        break

    def _scan_config_file(
        self, file_path: str, lines: List[str], 
        file_node_id: str, findings: List[VulnerabilityFinding], 
        nodes: List[GraphNode]
    ):
        for idx, line in enumerate(lines, start=1):
            line_str = line.strip()

            # Checa permissão de CORS com Wildcard '*'
            if '"AllowOrigins": "*"' in line_str or "'AllowOrigins': '*'" in line_str or 'cors_origins = "*"' in line_str:
                findings.append(VulnerabilityFinding(
                    id=f"CORS-{len(findings)+1:03d}",
                    rule_id="OWASP-A05-CORS-WILDCARD",
                    title="Configuração Insegura de CORS com Wildcard (*)",
                    severity=Severity.MEDIUM,
                    description="O arquivo de configuração permite requisições de qualquer origem de domínio (*).",
                    recommendation="Restrinja os origens permitidos apenas às URLs oficiais do frontend no Railway.",
                    location=FileLocation(
                        file_path=file_path,
                        line_start=idx,
                        snippet=line_str[:100]
                    ),
                    grc_mappings=[
                        GRCMapping(
                            framework=GRCFramework.OWASP_TOP_10,
                            control_id="A05:2021",
                            title="Security Misconfiguration",
                            description="CORS com wildcard expõe dados a ataques de origem cruzada."
                        )
                    ],
                    detected_by="ASTCodeScanner"
                ))
