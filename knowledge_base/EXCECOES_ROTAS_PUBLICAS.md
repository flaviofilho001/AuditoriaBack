# DIRETRIZES DE EXCEÇÃO E IDENTIFICAÇÃO DE ROTAS PÚBLICAS (GRC & OWASP)

## 1. Definição de Rotas Públicas Legítimas
Em arquiteturas de segurança de APIs RESTful e Web (C#, Go, Python, Java, Node.js), determinados endpoints de entrada **devem ser necessariamente públicos** e isentos de tokens de autenticação prévia (`[Authorize]`, `Bearer`, `JWT`).

Rotas legitimamente públicas incluem:
- **Autenticação e Login**: `/login`, `/signin`, `/auth/token`, `/oauth/token`
- **Cadastro de Usuários**: `/register`, `/signup`, `/criar-conta`
- **Recuperação e Troca de Senha**: `/forgot-password`, `/reset-password`
- **Diagnóstico e Telemetria**: `/health`, `/healthz`, `/status`, `/metrics`
- **Documentação de API**: `/swagger`, `/openapi.json`, `/docs`

## 2. Atributos e Decoradores de Isenção Nativos
Endpoints marcados explicitamente pelo desenvolvedor com as anotações abaixo **não devem ser considerados falha de controle de acesso**:
- C# (.NET): `[AllowAnonymous]`
- Java (Spring): `@PermitAll`, `@Anonymous`
- TypeScript / NestJS / Express: `@Public()`, `isPublicRoute`
- Python (FastAPI / Django): `@allow_anonymous`, `permission_classes = [AllowAny]`

## 3. Diretrizes de Auditoria e Resumo Executivo para a IA
- **Não Emitir Alerta de Ausência de Autorização**: Não sinalizar falta de `[Authorize]` para rotas de Login, Registro, Recuperação de Senha ou endpoints decorados com `[AllowAnonymous]`.
- **Foco Correto de Segurança**: Em rotas públicas de autenticação, o foco da auditoria deve ser a presença de **Rate Limiting (OWASP API4:2023 - Unrestricted Resource Consumption)**, sanitização de entrada e uso de HTTPS/TLS, e **NÃO** a exigência de login prévio.
- **Inexatidão a Evitar**: Jamais classificar um formulário público de cadastro ou formulário de login como "permitindo alteração não autorizada de perfis de terceiros" ou "data scraping", a menos que o endpoint exponha explicitamente dados de outros usuários no retorno.
