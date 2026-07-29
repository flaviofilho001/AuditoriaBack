import os
from pathlib import Path
from typing import Dict, List, Optional
import structlog

logger = structlog.get_logger()


class GRCKnowledgeRepository:
    """Repositório de consulta a normas e leis de GRC (LGPD, OWASP Top 10, ISO 27001)"""

    def __init__(self, base_dir: Optional[str] = None):
        if base_dir:
            self.base_dir = Path(base_dir)
        else:
            # Tenta resolver o diretório knowledge_base relativo à raiz do projeto
            current_file = Path(__file__).resolve()
            self.base_dir = current_file.parents[3] / "knowledge_base"

        self._cache: Dict[str, str] = {}
        self._load_all()

    def _load_all(self):
        if not self.base_dir.exists():
            logger.warning("grc_knowledge_base_not_found", path=str(self.base_dir))
            return

        for file_path in self.base_dir.glob("*.md"):
            try:
                content = file_path.read_text(encoding="utf-8")
                self._cache[file_path.stem.upper()] = content
                logger.info("grc_doc_loaded", file=file_path.name, size_bytes=len(content))
            except Exception as e:
                logger.error("grc_doc_load_failed", file=file_path.name, error=str(e))

    def get_document(self, name: str) -> Optional[str]:
        return self._cache.get(name.upper())

    def list_available_docs(self) -> List[str]:
        return list(self._cache.keys())

    def get_relevant_context(self, keywords: List[str], max_length: int = 2000) -> str:
        """Busca trechos relevantes na base GRC baseados em palavras-chave (ex: 'auth', 'senha', 'lgpd', 'cpf')."""
        context_snippets = []

        for doc_name, content in self._cache.items():
            lines = content.split("\n")
            for i, line in enumerate(lines):
                if any(kw.lower() in line.lower() for kw in keywords):
                    # Pega um bloco de 5 linhas ao redor
                    start = max(0, i - 2)
                    end = min(len(lines), i + 4)
                    block = "\n".join(lines[start:end])
                    context_snippets.append(f"[{doc_name}]\n{block}")
                    if len("\n---\n".join(context_snippets)) >= max_length:
                        break

        if not context_snippets:
            # Retorna o OWASP Top 10 resumido por padrão se nada específico for encontrado
            return self._cache.get("OWASP_TOP_10_2021", "")[:max_length]

        return "\n---\n".join(context_snippets)[:max_length]
