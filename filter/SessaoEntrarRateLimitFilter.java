package br.com.gruponeural.core.gateway.filter;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.logging.Logger;

import io.vertx.core.http.HttpServerRequest;
import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

/**
 * Rate limit simples em memória para {@code sessao/entrar} (proteção do gateway público).
 * Janela de 60s / 20 tentativas por IP. O IP vem de {@link #resolveClientKey}: o X-Forwarded-For só é
 * usado quando o IP remoto está em {@code gateway.proxies-confiaveis}.
 */
@Provider
@Priority(Priorities.AUTHENTICATION - 10)
public class SessaoEntrarRateLimitFilter implements ContainerRequestFilter {

  private static final Logger LOG = Logger.getLogger(SessaoEntrarRateLimitFilter.class);
  private static final int MAX_TENTATIVAS = 20;
  private static final Duration JANELA = Duration.ofSeconds(60);

  private volatile RateLimitContador contador;

  @Context
  HttpServerRequest httpServerRequest;

  private volatile ProxiesConfiaveis proxies;

  private RateLimitContador contador() {
    RateLimitContador c = contador;
    if (c == null) {
      synchronized (this) {
        c = contador;
        if (c == null) {
          long max = ConfigProvider.getConfig()
              .getOptionalValue("gateway.rate-limit.max-entradas", Long.class).orElse(10_000L);
          c = new RateLimitContador(max, JANELA);
          contador = c;
        }
      }
    }
    return c;
  }

  private ProxiesConfiaveis proxies() {
    ProxiesConfiaveis p = proxies;
    if (p == null) {
      p = ProxiesConfiaveis.of(ConfigProvider.getConfig()
          .getOptionalValues("gateway.proxies-confiaveis", String.class)
          .orElse(List.of()));
      proxies = p;
    }
    return p;
  }

  @Override
  public void filter(ContainerRequestContext requestContext) throws IOException {
    String path = requestContext.getUriInfo().getPath();
    if (path == null) {
      return;
    }
    String normalized = path.startsWith("/") ? path.substring(1) : path;
    if (!normalized.endsWith("sessao/entrar") && !normalized.contains("/sessao/entrar")) {
      return;
    }
    if (!"POST".equalsIgnoreCase(requestContext.getMethod())) {
      return;
    }

    String remoto = httpServerRequest != null && httpServerRequest.remoteAddress() != null
        ? httpServerRequest.remoteAddress().hostAddress()
        : null;
    String clientKey = resolveClientKey(requestContext.getHeaderString("X-Forwarded-For"), remoto, proxies());
    if (!contador().permitir(clientKey, MAX_TENTATIVAS)) {
      LOG.warnf("Rate limit sessao/entrar excedido (cliente %s)", RateLimitContador.hashParaLog(clientKey));
      requestContext.abortWith(
          Response.status(429)
              .entity(Map.of(
                  "mensagem",
                  Map.of(
                      "tipo", "AVISO",
                      "titulo", "Muitas tentativas de login.",
                      "detalhe", "Aguarde um minuto e tente novamente.")))
              .build());
    }
  }

  /**
   * Chave do cliente. Se o IP remoto for um proxy confiável, percorre o X-Forwarded-For da direita
   * para a esquerda e para no primeiro IP que não é proxy confiável. Se o remoto não for confiável
   * (ou a lista estiver vazia), ignora o header e usa o IP remoto.
   */
  static String resolveClientKey(String forwarded, String remoto, ProxiesConfiaveis proxies) {
    String atual = ProxiesConfiaveis.normalizarIp(remoto);
    if (atual == null) {
      return "unknown";
    }
    if (forwarded == null || proxies == null || proxies.isVazia() || !proxies.contem(atual)) {
      return atual;
    }
    String[] partes = forwarded.split(",");
    for (int i = partes.length - 1; i >= 0; i--) {
      String parte = partes[i].trim();
      if (parte.isEmpty()) {
        continue;
      }
      String ip = ProxiesConfiaveis.normalizarIp(parte);
      if (ip == null) {
        return atual;
      }
      atual = ip;
      if (!proxies.contem(ip)) {
        return ip;
      }
    }
    return atual;
  }
}
