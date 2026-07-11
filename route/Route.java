package br.com.gruponeural.core.gateway.route;

import java.util.ArrayList;

import org.apache.camel.Exchange;
import org.apache.camel.builder.RouteBuilder;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import br.com.gruponeural.core.gateway.security.JwtValidatorProcessor;
import br.com.gruponeural.core.gateway.security.PublicValidatorProcessor;
import jakarta.inject.Inject;

public abstract class Route
    extends RouteBuilder {

    @ConfigProperty(name = "quarkus.http.root-path", defaultValue = "/")
    String rootPath;

    @ConfigProperty(name = "gateway.bff.url")
    String gatewayBffUrl;

    @ConfigProperty(name = "gateway.http.connect-timeout", defaultValue = "10000")
    long gatewayHttpConnectTimeout;

    @ConfigProperty(name = "gateway.http.response-timeout", defaultValue = "60000")
    long gatewayHttpResponseTimeout;

    private String nomeServico;
    private String urlDestino;
    private ArrayList<RoutePath> listaPath = new ArrayList<>();

    @Inject
    JwtValidatorProcessor jwtValidatorProcessor;

    @Inject
    PublicValidatorProcessor publicValidatorProcessor;

    private void configurarTratamentoExecao() {

        String JSON_MENSAGEM_FALHA_AMIGAVEL = """
                {
                    "id": "${header.X-Correlation-ID}",
                    "mensagemTipo": "falha",
                    "mensagemTitulo": "Falha na comunicação com o servidor.",
                    "mensagemDetalhe": "Por favor, tente novamente mais tarde."
                }
            """;

        String JSON_MENSAGEM_ACESSO_NEGADO = """
                {
                    "id": "${header.X-Correlation-ID}",
                    "mensagemTipo": "falha",
                    "mensagemTitulo": "Acesso não autorizado.",
                    "mensagemDetalhe": "Assinatura do aplicativo inválida ou expirada."
                }
            """;

        onException(SecurityException.class)
            .handled(true)
            .setHeader("Content-Type", constant("application/json"))
            .setHeader("CamelHttpResponseCode", constant(401))
            .setBody(simple(JSON_MENSAGEM_ACESSO_NEGADO))
            .log("⚠️ [SECURITY] Tentativa de acesso negada: ${exception.message}")
            .log("🔙 [RESPOSTA] Status: ${header.CamelHttpResponseCode} de " + this.nomeServico)
            .log("📦 [BODY RESPOSTA]: ${body}")
            .process(exchange -> org.slf4j.MDC.remove("correlationId"));

        onException(Exception.class)
            .handled(true)
            .log("❌ [ERRO NO GATEWAY] Causa: ${exception.message}")
            .log("🔍 [STACKTRACE]: ${exception.stacktrace}")
            .setHeader("Content-Type", constant("application/json"))
            .setHeader("CamelHttpResponseCode", constant(500))
            .setBody(simple(JSON_MENSAGEM_FALHA_AMIGAVEL))
            .log("🔙 [RESPOSTA] Status: ${header.CamelHttpResponseCode} de " + this.nomeServico)
            .log("📦 [BODY RESPOSTA]: ${body}")
            .process(exchange -> org.slf4j.MDC.remove("correlationId"));

    }

    private void configurarRota(RoutePath path) {

        String prefixoCamel = this.nomeServico;

        String sufixo = path.getOrigem().startsWith("/") ? path.getOrigem() : "/" + path.getOrigem();
        String endpointFinal = ("/" + prefixoCamel + sufixo).replace("//", "/");

        String consumerUri = "platform-http:" + endpointFinal + "?httpMethodRestrict=" + path.getMetodo();
        if (path.isMatchOnUriPrefix()) {
            consumerUri += "&matchOnUriPrefix=true";
        }

        from(consumerUri)
            .routeId("gateway-" + this.nomeServico + "-" + path.getMetodo() + "-" + sufixo.replaceAll("[/\\?]", "-"))

            .process(exchange -> {
                String corrId = exchange.getIn().getHeader("X-Correlation-ID", String.class);
                boolean corrIdRecebido = corrId != null && !corrId.isBlank();
                if (corrId == null || corrId.isEmpty()) {
                    corrId = java.util.UUID.randomUUID().toString().substring(0, 8);
                }
                exchange.getIn().setHeader("X-Correlation-ID", corrId);
                exchange.getMessage().setHeader("X-Correlation-ID", corrId);
                org.slf4j.MDC.put("correlationId", corrId);
                exchange.setProperty("corrIdRecebido", corrIdRecebido);
            })

            .log("🧭 [CORRELATION] X-Correlation-ID=${header.X-Correlation-ID} | recebido=${exchangeProperty.corrIdRecebido}")
            .log("📥 [ENTRADA] Método: ${header.CamelHttpMethod} | Path: ${header.CamelHttpPath}")

            .choice()
            .when(constant(path.isPreserveBinaryBody()))
            .log("📝 [BODY ENTRADA]: <conteúdo binário/multipart omitido>")
            .process(exchange -> MultipartProxySupport.prepararProxyMultipart(exchange))
            .otherwise()
            .setBody(simple("${bodyAs(String)}"))
            .process(exchange -> {
                exchange.setProperty("safeBody", RouteHelper.mascararDadosSensiveis(exchange.getIn().getBody(String.class)));
            })
            .log("📝 [BODY ENTRADA]: ${exchangeProperty.safeBody}")
            .end()

            .process(exchange -> {
                String pathFinal = path.getDestino();
                if (path.isMatchOnUriPrefix()) {
                    String camelPath = exchange.getIn().getHeader(Exchange.HTTP_PATH, String.class);
                    if (camelPath == null || camelPath.isEmpty()) {
                        camelPath = exchange.getIn().getHeader("CamelHttpPath", String.class);
                    }
                    if (camelPath != null && camelPath.contains("?")) {
                        camelPath = camelPath.substring(0, camelPath.indexOf('?'));
                    }
                    String relMarker = prefixoCamel + "/" + path.getOrigem() + "/";
                    if (camelPath != null) {
                        int idx = camelPath.indexOf(relMarker);
                        if (idx >= 0) {
                            String tail = camelPath.substring(idx + relMarker.length());
                            if (!tail.isEmpty()) {
                                pathFinal = path.getDestino().replaceAll("/$", "") + "/" + tail;
                            }
                        }
                    }
                }
                exchange.getIn().setHeader("SubPath", pathFinal);
            })

            .log("🔒 [AUTH] Validando X-Signature e X-Timestamp...")
            .process(publicValidatorProcessor)
            .removeHeader("X-Signature")
            .removeHeader("X-Timestamp")

            .choice()
            .when(constant(path.getRequerAutenticacao()))
            .log("🔐 [AUTH] Validando token JWT...")
            .process(jwtValidatorProcessor)
            .removeHeader("Authorization")
            .end()

            .setHeader("TargetUrl", simple(urlDestino.replaceAll("/$", "") + "/${header.SubPath}"))

            .process(exchange -> {
                String q = exchange.getIn().getHeader(Exchange.HTTP_QUERY, String.class);
                if (q == null || q.isEmpty()) {
                    q = exchange.getIn().getHeader("CamelHttpQueryString", String.class);
                }
                if (q != null && !q.isEmpty()) {
                    exchange.getIn().setHeader(Exchange.HTTP_QUERY, q);
                }
            })

            .log("🚀 [PROXY] Encaminhando para: ${header.TargetUrl}")

            .removeHeader("CamelHttpPath")
            .removeHeader("CamelHttpQueryString")

            .choice()
            .when(constant(path.isPreserveBinaryBody()))
            .process(exchange -> RouteHelper.finalizarHeadersProxyBinario(exchange))
            .toD("${header.TargetUrl}?bridgeEndpoint=true&throwExceptionOnFailure=false&copyHeaders=false&connectTimeout="
                + gatewayHttpConnectTimeout + "&responseTimeout=" + gatewayHttpResponseTimeout)
            .otherwise()
            .toD("${header.TargetUrl}?bridgeEndpoint=true&throwExceptionOnFailure=false&copyHeaders=true&connectTimeout="
                + gatewayHttpConnectTimeout + "&responseTimeout=" + gatewayHttpResponseTimeout)
            .end()

            .choice()
            .when(simple("${header.Content-Type} regex '(?i).*(image/|application/octet-stream).*'"))
            .log("🔙 [RESPOSTA] Status: ${header.CamelHttpResponseCode} de " + this.nomeServico + " (binário)")
            .otherwise()
            .process(exchange -> {
                String text = RouteHelper.bodyRespostaComoTexto(exchange);
                exchange.getIn().setBody(text);
                exchange.setProperty("safeResponse", RouteHelper.mascararDadosSensiveis(text));
            })
            .log("🔙 [RESPOSTA] Status: ${header.CamelHttpResponseCode} de " + this.nomeServico)
            .log("📦 [BODY RESPOSTA]: ${exchangeProperty.safeResponse}")
            .setHeader("Content-Type", constant("application/json"))
            .end()

            .process(exchange -> org.slf4j.MDC.remove("correlationId"));
    }

    protected void configurarServico(String nomeServico) {
        this.nomeServico = nomeServico.toLowerCase();
    }

    protected void configurarUrlDestino(String urlDestino) {
        this.urlDestino = urlDestino;
    }

    protected void configurarUrlDestinoBff() {
        configurarUrlDestino(gatewayBffUrl);
    }

    protected void adicionarRota(RoutePath path) {
        this.listaPath.add(path);
    }

    @Override
    public void configure() {

        this.configurarTratamentoExecao();
        this.listaPath.forEach(this::configurarRota);

    }

}
