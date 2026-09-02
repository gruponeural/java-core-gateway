package br.com.gruponeural.core.gateway.proxy;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import br.com.gruponeural.core.gateway.filter.CorrelationIdFilter;
import br.com.gruponeural.core.gateway.route.GatewayRouteRegistry;
import br.com.gruponeural.core.gateway.route.MultipartProxySupport;
import br.com.gruponeural.core.gateway.route.RegisteredRoute;
import br.com.gruponeural.core.gateway.route.RouteHelper;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

@ApplicationScoped
public class GatewayProxyService {

  private static final Logger LOG = Logger.getLogger(GatewayProxyService.class);

  private static final Set<String> HOP_BY_HOP_HEADERS = Set.of(
      "connection",
      "keep-alive",
      "proxy-authenticate",
      "proxy-authorization",
      "te",
      "trailers",
      "transfer-encoding",
      "upgrade",
      "host",
      "content-length",
      "authorization",
      "x-signature",
      "x-timestamp");

  @ConfigProperty(name = "gateway.http.connect-timeout", defaultValue = "10000")
  long gatewayHttpConnectTimeout;

  @ConfigProperty(name = "gateway.http.response-timeout", defaultValue = "180000")
  long gatewayHttpResponseTimeout;

  @Inject
  GatewayRouteRegistry routeRegistry;

  private HttpClient httpClient;

  @PostConstruct
  void init() {
    httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofMillis(gatewayHttpConnectTimeout))
        .followRedirects(HttpClient.Redirect.NORMAL)
        .build();
  }

  public Response proxy(
      String method,
      String servico,
      String pathSuffix,
      ContainerRequestContext requestContext,
      UriInfo uriInfo) throws IOException, InterruptedException {

    RegisteredRoute route = (RegisteredRoute) requestContext.getProperty(GatewayRouteRegistry.MATCHED_ROUTE_PROPERTY);
    if (route == null) {
      route = routeRegistry.match(servico, method, pathSuffix).orElse(null);
    }
    if (route == null) {
      return Response.status(Response.Status.NOT_FOUND).build();
    }

    String subPath = route.resolveDestino(pathSuffix);
    String base = route.resolveBaseUrl(routeRegistry);
    String targetUrl = base.replaceAll("/$", "") + "/" + subPath.replaceAll("^/", "");

    String query = uriInfo.getRequestUri().getRawQuery();
    if (query != null && !query.isBlank()) {
      targetUrl = targetUrl + "?" + query;
    }

    byte[] requestBody = readRequestBody(requestContext);
    String contentType = requestContext.getHeaderString(HttpHeaders.CONTENT_TYPE);
    boolean preserveBinary = route.path().isPreserveBinaryBody();

    if (preserveBinary) {
      LOG.info("📝 [BODY ENTRADA]: <conteúdo binário/multipart omitido>");
      requestBody = prepararBodyBinario(requestBody, contentType, requestContext);
      contentType = requestContext.getHeaderString(HttpHeaders.CONTENT_TYPE);
    } else if (requestBody != null && requestBody.length > 0) {
    String safeBody = RouteHelper.mascararDadosSensiveis(new String(requestBody, java.nio.charset.StandardCharsets.UTF_8));
    LOG.infof("📝 [BODY ENTRADA]: %s", safeBody);
    requestBody = RouteHelper.prepararBodyJsonParaProxy(new String(requestBody, java.nio.charset.StandardCharsets.UTF_8));
    contentType = MediaType.APPLICATION_JSON + ";charset=UTF-8";
  }

    LOG.infof("🚀 [PROXY] Encaminhando para: %s", targetUrl);

    HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
        .uri(URI.create(targetUrl))
        .timeout(Duration.ofMillis(gatewayHttpResponseTimeout))
        .method(method, bodyPublisher(method, requestBody));

    copiarHeaders(requestContext, requestBuilder, contentType);

    HttpResponse<byte[]> downstream = httpClient.send(
        requestBuilder.build(),
        HttpResponse.BodyHandlers.ofByteArray());

    String responseContentType = downstream.headers().firstValue("Content-Type").orElse(null);
    byte[] responseBody = downstream.body();

    if (RouteHelper.isRespostaBinaria(responseContentType)) {
      LOG.infof("🔙 [RESPOSTA] Status: %d de %s (binário)", downstream.statusCode(), route.servico());
      return Response.status(downstream.statusCode())
          .entity(responseBody)
          .type(responseContentType != null ? responseContentType : MediaType.APPLICATION_OCTET_STREAM)
          .build();
    }

    String responseText = responseBody == null ? null : new String(responseBody, java.nio.charset.StandardCharsets.UTF_8);
    String safeResponse = RouteHelper.mascararDadosSensiveis(responseText);
    LOG.infof("🔙 [RESPOSTA] Status: %d de %s", downstream.statusCode(), route.servico());
    LOG.infof("📦 [BODY RESPOSTA]: %s", safeResponse);

    // Preservar Content-Type do MS (ex.: text/plain em status/logs); JSON só como fallback.
    String outboundType =
        responseContentType != null && !responseContentType.isBlank()
            ? responseContentType
            : MediaType.APPLICATION_JSON;
    return Response.status(downstream.statusCode())
        .entity(responseText)
        .type(outboundType)
        .build();
  }

  private byte[] prepararBodyBinario(byte[] body, String contentType, ContainerRequestContext requestContext)
      throws IOException {
    Map<String, String> multipartHeaders = new HashMap<>();
    for (Map.Entry<String, List<String>> entry : requestContext.getHeaders().entrySet()) {
      if (entry.getValue() != null && !entry.getValue().isEmpty()) {
        multipartHeaders.put(entry.getKey().toLowerCase(Locale.ROOT), entry.getValue().getFirst());
      }
    }

    byte[] original = body;
    byte[] prepared = MultipartProxySupport.prepararProxyMultipart(body, contentType, multipartHeaders);
    if (prepared == null) {
      return RouteHelper.prepararBodyBinarioParaProxy(body);
    }
    if (original != null
        && !MultipartProxySupport.iniciaComMultipart(original)
        && MultipartProxySupport.iniciaComMultipart(prepared)) {
      String boundary = MultipartProxySupport.boundaryFromMultipart(prepared);
      requestContext.getHeaders().putSingle(HttpHeaders.CONTENT_TYPE, "multipart/form-data; boundary=" + boundary);
    }
    return prepared;
  }

  private static HttpRequest.BodyPublisher bodyPublisher(String method, byte[] body) {
    if ("GET".equalsIgnoreCase(method) || "HEAD".equalsIgnoreCase(method) || "DELETE".equalsIgnoreCase(method)) {
      return HttpRequest.BodyPublishers.noBody();
    }
    if (body == null) {
      return HttpRequest.BodyPublishers.noBody();
    }
    return HttpRequest.BodyPublishers.ofByteArray(body);
  }

  private void copiarHeaders(
      ContainerRequestContext requestContext,
      HttpRequest.Builder requestBuilder,
      String contentType) {

    String correlationId = requestContext.getHeaderString(CorrelationIdFilter.CORRELATION_HEADER);
    if (correlationId != null && !correlationId.isBlank()) {
      requestBuilder.header(CorrelationIdFilter.CORRELATION_HEADER, correlationId);
    }

    for (Map.Entry<String, List<String>> entry : requestContext.getHeaders().entrySet()) {
      String name = entry.getKey();
      if (name == null || HOP_BY_HOP_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
        continue;
      }
      if (HttpHeaders.CONTENT_TYPE.equalsIgnoreCase(name)) {
        continue;
      }
      if (CorrelationIdFilter.CORRELATION_HEADER.equalsIgnoreCase(name)) {
        continue;
      }
      for (String value : entry.getValue()) {
        requestBuilder.header(name, value);
      }
    }

    if (contentType != null && !contentType.isBlank()) {
      requestBuilder.header(HttpHeaders.CONTENT_TYPE, contentType);
    }
  }

  private static byte[] readRequestBody(ContainerRequestContext requestContext) throws IOException {
    if (!requestContext.hasEntity()) {
      return null;
    }
    try (InputStream inputStream = requestContext.getEntityStream()) {
      return inputStream.readAllBytes();
    }
  }

}
