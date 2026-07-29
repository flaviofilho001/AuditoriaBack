import json
from typing import Dict, Any, List
from src.domain.models.vulnerability import VulnerabilityFinding, Severity


class SarifReporter:
    """Gerador de Relatórios no formato padrão SARIF v2.1.0 (Static Analysis Results Interchange Format) para GitHub Security Scanning."""

    @staticmethod
    def generate_sarif(scan_result: Dict[str, Any]) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = scan_result.get("findings", [])

        sarif_rules = []
        sarif_results = []
        rule_ids_seen = set()

        for f in findings:
            rule_id = f.get("rule_id", "GENERIC-VULN")
            
            # Adiciona definição da regra no driver
            if rule_id not in rule_ids_seen:
                rule_ids_seen.add(rule_id)
                sarif_rules.append({
                    "id": rule_id,
                    "name": f.get("title", rule_id),
                    "shortDescription": {"text": f.get("title", rule_id)},
                    "fullDescription": {"text": f.get("description", "")},
                    "help": {
                        "text": f.get("recommendation", ""),
                        "markdown": f"### Recomendação GRC\n{f.get('recommendation', '')}"
                    },
                    "properties": {
                        "security-severity": "9.0" if f.get("severity") == "CRITICAL" else "7.0" if f.get("severity") == "HIGH" else "4.0"
                    }
                })

            # Converte nível de gravidade para SARIF (error, warning, note)
            level = "error" if f.get("severity") in ["CRITICAL", "HIGH"] else "warning" if f.get("severity") == "MEDIUM" else "note"
            
            loc = f.get("location", {})
            file_path = loc.get("file_path", "unknown")
            line_start = loc.get("line_start", 1)

            sarif_results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"{f.get('title')}: {f.get('description')}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_path
                            },
                            "region": {
                                "startLine": line_start
                            }
                        }
                    }
                ]
            })

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Auditor de Conformidade de APIs",
                            "version": "1.0.0",
                            "informationUri": "https://auditoriafront-production.up.railway.app",
                            "rules": sarif_rules
                        }
                    },
                    "results": sarif_results
                }
            ]
        }
