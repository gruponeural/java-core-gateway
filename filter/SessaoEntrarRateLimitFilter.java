package br.com.gruponeural.core.gateway.filter;

import java.io.IOException;
import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.jboss.logging.Logger;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

/**
 * Rate limit simples em memória para {@code sessao/entrar} (proteção do gateway público).
 * Janela de 60s / 20 tentativas por IP (ou 10.0.0.0 se o remoto for nulo).
 */
@Provider
@Priority(Priorities.AUTHENTICATION - 10)
public class SessaoEntrarRateLimitFilter implements ContainerRequestFilter {

  private static final Logger LOG = Logger.getLogger(SessaoEntrarRateLimitFilter.class);
  private static final int MAX_TENTATIVAS = 20;
  private static final long JANELA_MS = 60_000L;

  private static final ConcurrentHashMap<String, Window> WINDOWS = new ConcurrentHashMap<>();

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

    String clientKey = resolveClientKey(requestContext);
    long now = Instant.now().toEpochMilli();
    purgeExpired(now);

    Window window = WINDOWS.compute(clientKey, (k, existing) -> {
      if (existing == null || now - existing.startedAtMs >= JANELA_MS) {
        return new Window(now);
      }
      existing.count.incrementAndGet();
      return existing;
    });

    if (window.count.get() > MAX_TENTATIVAS) {
      LOG.warnf("Rate limit sessao/entrar excedido para %s", clientKey);
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

  private static String resolveClientKey(ContainerRequestContext ctx) {
    String forwarded = ctx.getHeaderString("X-Forwarded-For");
    if (forwarded != null && !forwarded.isBlank()) {
      return forwarded.split(",")[0].trim();
    }
    return "unknown";
  }

  private static void purgeExpired(long now) {
    if (WINDOWS.size() < 1000) {
      return;
    }
    Iterator<Map.Entry<String, Window>> it = WINDOWS.entrySet().iterator();
    while (it.hasNext()) {
      Map.Entry<String, Window> e = it.next();
      if (now - e.getValue().startedAtMs >= JANELA_MS) {
        it.remove();
      }
    }
  }

  private static final class Window {
    final long startedAtMs;
    final AtomicInteger count = new AtomicInteger(1);

    Window(long startedAtMs) {
      this.startedAtMs = startedAtMs;
    }
  }
}
