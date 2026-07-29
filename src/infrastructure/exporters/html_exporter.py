from typing import Dict, Any, List
import datetime


class HTMLExecutiveReporter:
    """Gerador de Relatório HTML Executivo Baixável com design profissional e métricas GRC."""

    @staticmethod
    def generate_html(scan_result: Dict[str, Any]) -> str:
        summary = scan_result.get("summary", {})
        findings: List[Dict[str, Any]] = scan_result.get("findings", [])
        sev_counts = summary.get("severity_counts", {})
        ai_summary = summary.get("ai_executive_summary", "")
        now_str = datetime.datetime.now().strftime("%d/%m/%Y às %H:%M")

        findings_html = ""
        for f in findings:
            sev = f.get("severity", "LOW")
            badge_class = f"badge-{sev.lower()}"
            loc = f.get("location", {})

            grc_html = ""
            for g in f.get("grc_mappings", []):
                grc_html += f"<li><strong>{g.get('framework')} ({g.get('control_id')}):</strong> {g.get('title')}</li>"

            findings_html += f"""
            <div class="card finding-card severity-{sev.lower()}">
                <div class="finding-header">
                    <div>
                        <span class="badge {badge_class}">{sev}</span>
                        <span class="rule-id">{f.get('rule_id')}</span>
                        <h3>{f.get('title')}</h3>
                    </div>
                    <div class="location-tag">{loc.get('file_path')}:{loc.get('line_start')}</div>
                </div>
                <p class="description">{f.get('description')}</p>
                {f'<pre class="code-snippet"><code>{loc.get("snippet")}</code></pre>' if loc.get("snippet") else ''}
                <div class="grc-box">
                    <div class="grc-title">CONTROLES GRC AFETADOS:</div>
                    <ul>{grc_html}</ul>
                    <div class="recommendation"><strong>Recomendação:</strong> {f.get('recommendation')}</div>
                </div>
            </div>
            """

        html_template = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Relatório Executivo de Conformidade GRC</title>
    <style>
        body {{ font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px 20px; line-height: 1.6; }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        .header {{ text-align: center; margin-bottom: 40px; border-bottom: 1px solid #334155; padding-bottom: 20px; }}
        .header h1 {{ color: #6366f1; margin: 0 0 10px 0; font-size: 2rem; }}
        .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 30px; }}
        .metric-card {{ background: #1e293b; padding: 20px; border-radius: 12px; border: 1px solid #334155; text-align: center; }}
        .metric-card .value {{ font-size: 2rem; font-weight: 800; color: #38bdf8; }}
        .metric-card .label {{ font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; }}
        .ai-box {{ background: rgba(99, 102, 241, 0.1); border-left: 4px solid #6366f1; padding: 20px; border-radius: 8px; margin-bottom: 30px; }}
        .ai-box h3 {{ margin: 0 0 10px 0; color: #818cf8; }}
        .finding-card {{ background: #1e293b; border-radius: 12px; padding: 20px; margin-bottom: 20px; border: 1px solid #334155; }}
        .severity-critical {{ border-left: 5px solid #f43f5e; }}
        .severity-high {{ border-left: 5px solid #f59e0b; }}
        .severity-medium {{ border-left: 5px solid #06b6d4; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; text-transform: uppercase; }}
        .badge-critical {{ background: rgba(244, 63, 94, 0.2); color: #f43f5e; }}
        .badge-high {{ background: rgba(245, 158, 11, 0.2); color: #f59e0b; }}
        .badge-medium {{ background: rgba(6, 182, 212, 0.2); color: #06b6d4; }}
        .rule-id {{ color: #64748b; font-family: monospace; font-size: 0.85rem; margin-left: 8px; }}
        .location-tag {{ background: #0f172a; padding: 4px 8px; border-radius: 4px; font-family: monospace; font-size: 0.8rem; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; }}
        .finding-header h3 {{ margin: 6px 0 0 0; font-size: 1.1rem; }}
        .code-snippet {{ background: #090d16; padding: 12px; border-radius: 6px; font-family: monospace; overflow-x: auto; color: #38bdf8; font-size: 0.85rem; }}
        .grc-box {{ background: rgba(255,255,255,0.02); padding: 12px; border-radius: 6px; margin-top: 12px; font-size: 0.85rem; }}
        .grc-title {{ color: #818cf8; font-weight: bold; margin-bottom: 6px; }}
        .recommendation {{ margin-top: 8px; color: #34d399; }}
        .footer {{ text-align: center; margin-top: 40px; color: #64748b; font-size: 0.8rem; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Relatório Executivo de Conformidade GRC</h1>
            <p style="color: #94a3b8; margin: 0;">Auditoria de Segurança de APIs • Gerado em {now_str}</p>
        </div>

        <div class="metrics">
            <div class="metric-card">
                <div class="value" style="color: #f43f5e;">{sev_counts.get('CRITICAL', 0)}</div>
                <div class="label">Risco Crítico</div>
            </div>
            <div class="metric-card">
                <div class="value" style="color: #f59e0b;">{sev_counts.get('HIGH', 0)}</div>
                <div class="label">Risco Alto</div>
            </div>
            <div class="metric-card">
                <div class="value">{summary.get('total_files_scanned', 0)}</div>
                <div class="label">Arquivos Analisados</div>
            </div>
            <div class="metric-card">
                <div class="value" style="color: #34d399;">{summary.get('graph_summary', {{}}).get('endpoints_count', 0)}</div>
                <div class="label">Endpoints Mapeados</div>
            </div>
        </div>

        {"<div class='ai-box'><h3>🤖 Parecer Executivo da IA (gemini-3.5-flash)</h3><div>" + ai_summary.replace("\n", "<br>") + "</div></div>" if ai_summary else ""}

        <h2>🚨 Achados de Conformidade Mapeados ({len(findings)})</h2>
        {findings_html if findings else "<p style='color:#94a3b8;'>Nenhum risco de segurança encontrado no repositório.</p>"}

        <div class="footer">
            Auditor de Conformidade de APIs • OWASP Top 10 • LGPD Art. 46 • ISO 27001
        </div>
    </div>
</body>
</html>"""
        return html_template
