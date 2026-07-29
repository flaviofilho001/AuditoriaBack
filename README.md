# AuditoriaBack - Engine & Backend do Auditor de Conformidade de APIs

Backend em Python 3.11 com **Clean Architecture**, **FastAPI**, **GraphRAG**, **Tree-sitter AST Scanner** e **Base de Conhecimento GRC (OWASP Top 10, LGPD Art. 46, ISO 27001)**.

## Provedores de LLM Suportados
1. **Google Gemini (Com Rate Limiter de 14 RPM)**:
   - Throttling automático para não ultrapassar 14 requisições por minuto.
   - Requer `GEMINI_API_KEY`.
2. **Ollama Local**:
   - Conecta ao Ollama em `http://localhost:11434`.
   - Suporta modelos locais como `gemma:2b`, `gemma:12b`, `gemma:26b`, `qwen3.5:2b`, `llama3.2`, etc.

## Como Rodar Localmente

```bash
cd AuditoriaBack
pip install -r requirements.txt
python -m uvicorn src.presentation.api.main:app --reload --port 8000
```

Acesse a documentação da API em: `http://localhost:8000/docs`

## Deploy no Railway

Suba esta pasta (`AuditoriaBack`) como um repositório Git separado no Railway. O Railway detectará o `Dockerfile` automaticamente.
