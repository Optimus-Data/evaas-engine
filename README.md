# evaas-engine

Runtime de validação e normalização de dados, escrito em Rust, com foco em **latência extremamente baixa (~1ms)** e execução local.

## 🚩 Problema

Validação de dados está espalhada no código.

- Cada sistema implementa de um jeito
- Cada linguagem tem sua própria biblioteca
- Regras divergentes entre serviços
- Difícil auditar o que está em produção

## 💡 Proposta

O EVaaS trata validação como **infraestrutura**, não como código.

- Execução local (sem dependência de rede)
- Latência previsível (hot path safe)
- Catálogo de regras reutilizáveis
- Base para governança central (opcional)

## ⚙️ Características

- Escrita em Rust
- Stateless
- Execução in-memory
- Suporte a validação e normalização
- Catálogo inicial (CPF, CNPJ, nomes, texto, etc)

## 📦 Exemplo

```bash
curl -s http://localhost:10012/v1/validate/field \
  -H "content-type: application/json" \
  -d '{
    "ruleId":"br.cnpj",
    "value":"12.ABC.345/01DE-35",
    "options":{"locale":"pt-BR","mode":"strict"}
  }'
