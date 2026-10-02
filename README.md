# java-core-gateway

Infraestrutura compartilhada dos gateways Grupo Neural (Camel, JWT, assinatura pública, health).

## Pacotes

| Pacote | Conteúdo |
|--------|----------|
| `br.com.gruponeural.core.gateway.route` | `Route`, `RoutePath`, `RouteHelper` |
| `br.com.gruponeural.core.gateway.security` | `JwtValidatorProcessor`, `SessaoGatewayValidator`, `PublicValidatorProcessor` |
| `br.com.gruponeural.core.gateway.health` | `HealthCheckImpl` |

## Submodule

Path no repo pai: `src/main/java/br/com/gruponeural/core/gateway`

Requer também o submodule **`java-core-geral`** (`core/geral`) para `SessaoConst`.

## Configuração (`application.properties`)

```properties
gateway.bff.url=http://localhost:5001/gruponeural/aproveitemais/bff
gateway.identity.header=X-Id-Pessoa
gateway.identity.query-param=idPessoa
gateway.health.name=Aproveite Mais - Gateway Health Check
app.sessao.url=http://localhost:4200/gruponeural/aproveitemais/sessao
public.validator.secret=...
```

Cortex / Central Controle usam `X-Id-Usuario` e `idUsuario` (defaults).

## Assinatura pública (`X-Signature` / `X-Timestamp` / `X-GN-Client`)

| Cliente | Secret | Rotas |
|---------|--------|-------|
| `site` | `public.validator.secret` | todas as públicas, menos as de cliente exclusivo |
| `mobile` | `public.validator.secret.mobile` | idem |
| `monitoramento` | `public.validator.secret.monitoramento` | só rotas com `somenteCliente("monitoramento")` |

```java
new RoutePath("monitoramento/stack", "v1/monitoramento/stack", "GET", false).somenteCliente("monitoramento")
```

O Cortex não usa o cliente `monitoramento` (fica fora do monitoramento dos produtos).
