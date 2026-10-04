# ChinaBet MVP v14 — Hardening

## Incluído
- Validação mais rígida de configuração.
- Proteção explícita contra ativação de dinheiro real neste pacote.
- Health check.
- Endpoint de safety/config.
- Testes automatizados com pytest.
- Migrations versionadas e tabela `schema_migrations`.
- Índices de segurança para sessões/auditoria.
- Separação entre app e migrações.
- CORS configurável.
- Documentação Swagger desativável em produção.
- RBAC/sessões/auditoria preservados da etapa anterior.

## Execução
`docker compose up --build`

Testes:
`cd backend && pytest -q`

Frontend: http://localhost:8080
API: http://localhost:8000

## Observação
Este é um scaffold técnico. Antes de produção: revisão de segurança, gestão de secrets, TLS, WAF, rate limiting distribuído, observabilidade externa, backups, disaster recovery, migrations formais e validação jurídica/licenciamento.
