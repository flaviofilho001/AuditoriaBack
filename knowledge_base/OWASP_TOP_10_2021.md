# OWASP Top 10:2021 - Padrões de Segurança para APIs e Código-Fonte

## A01:2021 – Quebra de Controle de Acesso (Broken Access Control)
- **Descrição**: Falha na imposição de restrições sobre o que os usuários autenticados ou anônimos podem fazer.
- **Risco em APIs**: Endpoints expostos sem atributos de autenticação/autorização (`[Authorize]`, `@PreAuthorize`, middleware JWT), BOLA/IDOR (Broken Object Level Authorization - p.ex. acessar `/users/{id}` trocando o ID sem validar se pertence ao usuário logado).
- **Controle GRC**: OWASP A01 | ISO 27001 A.8.2 (Controle de Acesso) | LGPD Art. 46.

## A02:2021 – Falhas Criptográficas (Cryptographic Failures)
- **Descrição**: Falta ou fraqueza na proteção de dados sensíveis em trânsito e em repouso.
- **Risco em APIs**: Senhas ou tokens gravados em plaintext no banco de dados, conexão HTTP sem TLS/HTTPS, algoritmos de hash fracos (MD5, SHA1), ausência de criptografia em campos de PII (CPF, Cartão, Email).
- **Controle GRC**: OWASP A02 | ISO 27001 A.8.24 (Uso de Criptografia) | LGPD Art. 46.

## A03:2021 – Injeção (Injection)
- **Descrição**: Entrada de dados não sanitizada ou não parametrizada enviada para um interpretador (SQL, NoSQL, OS Command, ORM).
- **Risco em APIs**: Concatenação direta de strings em queries SQL (`SELECT * FROM users WHERE name = '` + input + `'`), Execução de comandos do sistema via input do usuário (`exec(input)`).
- **Controle GRC**: OWASP A03 | ISO 27001 A.8.28 (Codificação Segura).

## A04:2021 – Design Inseguro (Insecure Design)
- **Descrição**: Deficiências de arquitetura e design de segurança antes da implementação.
- **Risco em APIs**: Ausência de limite de taxa (Rate Limiting) em endpoints sensíveis (Login, Reset Password), ausência de validação de fluxo de negócios.
- **Controle GRC**: OWASP A04 | ISO 27001 A.8.25 (Ciclo de Desenvolvimento Seguro).

## A05:2021 – Configuração Incorreta de Segurança (Security Misconfiguration)
- **Descrição**: Configurações padrão inseguras, permissões excessivas, mensagens de erro detalhadas expostas.
- **Risco em APIs**: CORS configurado com wildcard `*` e `AllowCredentials`, segredos hardcoded em arquivos de configuração (`appsettings.json`, `.env`), stack traces detalhados devolvidos nas respostas HTTP.
- **Controle GRC**: OWASP A05 | ISO 27001 A.8.9 (Gerenciamento de Configuração).

## A06:2021 – Componentes Vulneráveis e Desatualizados (Vulnerable and Outdated Components)
- **Descrição**: Uso de bibliotecas de terceiros com vulnerabilidades conhecidas (CVEs).
- **Risco em APIs**: Dependências com vulnerabilidades em `packages.lock.json`, `go.mod`, `requirements.txt`, `pom.xml`.
- **Controle GRC**: OWASP A06 | ISO 27001 A.8.30 (Gestão de Vulnerabilidades de Software).

## A07:2021 – Falhas de Identificação e Autenticação (Identification and Authentication Failures)
- **Descrição**: Confirmação incorreta da identidade do usuário, permitindo engenharia reversa ou brute force.
- **Risco em APIs**: Ausência de expiração ou revogação de tokens JWT, senhas fracas permitidas, reutilização de tokens de sessão.
- **Controle GRC**: OWASP A07 | ISO 27001 A.8.5 (Autenticação Forte).

## A08:2021 – Falhas de Integridade de Software e Dados (Software and Data Integrity Failures)
- **Descrição**: Código e infraestrutura que não protegem contra violações de integridade (deserialização insegura, CI/CD sem verificação).
- **Risco em APIs**: Deserialização de objetos de origens não confiáveis sem validação de esquema.
- **Controle GRC**: OWASP A08 | ISO 27001 A.8.28.

## A09:2021 – Falhas de Registro e Monitoramento de Segurança (Security Logging and Monitoring Failures)
- **Descrição**: Falha em registrar, rastrear ou alertar sobre atividades suspeitas.
- **Risco em APIs**: Ausência de logs para tentativas de login falhas ou ações críticas; ou o inverso: vazamento de dados sensíveis (senhas, CPF, cartões) dentro dos arquivos de log.
- **Controle GRC**: OWASP A09 | ISO 27001 A.8.15 (Registros de Eventos - Logging) | LGPD Art. 46.

## A10:2021 – Falsificação de Requisição do Lado do Servidor (SSRF - Server-Side Request Forgery)
- **Descrição**: A aplicação web busca um recurso remoto sem validar a URL fornecida pelo usuário.
- **Risco em APIs**: API recebe uma URL como parâmetro e faz requisição HTTP para a rede interna/localhost sem sanitização.
- **Controle GRC**: OWASP A10 | ISO 27001 A.8.28.
