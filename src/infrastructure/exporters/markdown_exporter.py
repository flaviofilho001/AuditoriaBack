from typing import Dict, Any, List


class MarkdownPRReporter:
    """Gerador de Relatórios formatados em Markdown para comentários automáticos de Bot em Pull Requests no GitHub / Azure DevOps."""

    @staticmethod
    def generate_markdown(scan_result: Dict[str, Any]) -> str:
        summary = scan_result.get("summary", {})
        findings: List[Dict[str, Any]] = scan_result.get("findings", [])
        sev_counts = summary.get("severity_counts", {})
        ai_summary = summary.get("ai_executive_summary", "")

        md_lines = []
        md_lines.append("# 🛡️ Relatório do Auditor de Conformidade GRC & IA")
        md_lines.append("")
        md_lines.append("A verificação estática (AST), o Grafo de Código (GraphRAG) e a IA analisaram os arquivos deste projeto.")
        md_lines.append("")

        # Tabela de Resumo de Gravidade
        md_lines.append("### 📊 Resumo de Riscos")
        md_lines.append("| Gravidade | Quantidade |")
        md_lines.append("| :--- | :--- |")
        md_lines.append(f"| 🔴 **CRITICAL** | {sev_counts.get('CRITICAL', 0)} |")
        md_lines.append(f"| 🟠 **HIGH** | {sev_counts.get('HIGH', 0)} |")
        md_lines.append(f"| 🟡 **MEDIUM** | {sev_counts.get('MEDIUM', 0)} |")
        md_lines.append(f"| 🟢 **LOW** | {sev_counts.get('LOW', 0)} |")
        md_lines.append("")

        # Resumo Executivo da IA
        if ai_summary:
            md_lines.append("### 🤖 Parecer Executivo da IA (gemini-3.5-flash)")
            md_lines.append(f"> {ai_summary.replace(chr(10), chr(10) + '> ')}")
            md_lines.append("")

        # Detalhamento dos Achados
        md_lines.append("### 🚨 Achados Detectados")
        if not findings:
            md_lines.append("✅ Nenhuma vulnerabilidade ou não-conformidade foi identificada neste escaneamento!")
        else:
            md_lines.append("| Regra | Gravidade | Localização | Descrição & Correção |")
            md_lines.append("| :--- | :--- | :--- | :--- |")
            for f in findings:
                loc = f.get("location", {})
                loc_str = f"`{loc.get('file_path')}:{loc.get('line_start')}`"
                sev_icon = "🔴" if f.get("severity") == "CRITICAL" else "🟠" if f.get("severity") == "HIGH" else "🟡"
                desc_text = f"**{f.get('title')}**<br>{f.get('description')}<br>*Recomendação:* {f.get('recommendation')}"
                md_lines.append(f"| `{f.get('rule_id')}` | {sev_icon} {f.get('severity')} | {loc_str} | {desc_text} |")

        md_lines.append("")
        md_lines.append("---")
        md_lines.append("*Gerado automaticamente pelo [Auditor de Conformidade de APIs](https://auditoriafront-production.up.railway.app)*")

        return "\n".join(md_lines)
