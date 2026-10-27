package br.com.gruponeural.core.gateway.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Optional;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.logging.Logger;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;

/**
 * Rate limit por usuário de {@code localizacao/bairro/criar}, depois da autenticação.
 * Usa o upn já validado por {@link GatewayJwtAuthFilter} (propriedade do request), nunca o JWT cru.
 */
@Provider
@Priority(Priorities.AUTHENTICATION + 20)
public class RateLimitBairroUsuarioFilter implements ContainerRequestFilter {

  private static final Logger LOG = Logger.getLogger(RateLimitBairroUsuarioFilter.class);

  static final String PATH = "localizacao/bairro/criar";
  static final int LIMITE_USUARIO_PADRAO = 5;
  static final String PROP_LIMITE = "gateway.rate-limit.bairro-criar.limite";

  private volatile Estado estado;

  private record Estado(RateLimitContador contador, int limite, long janelaSegundos) {
  }

  @Override
  public void filter(ContainerRequestContext requestContext) throws IOException {
    if (!"POST".equalsIgnoreCase(requestContext.getMethod())) {
      return;
    }
    String path = normalizar(requestContext.getUriInfo().getPath());
    if (!PATH.equals(path)) {
      return;
    }
    Optional<String> chave = chaveUsuarioValidado(
        requestContext.getProperty(GatewayJwtAuthFilter.UPN_VALIDADO_PROPERTY));
    if (chave.isEmpty()) {
      return;
    }
    Estado e = estado();
    if (!e.contador().permitir(path + "|" + chave.get(), e.limite())) {
      LOG.warnf("Rate limit bairro-criar (usuario) excedido em %s", path);
      String correlationId = org.slf4j.MDC.get("correlationId");
      requestContext.abortWith(RateLimitFilter.resposta429(correlationId, e.janelaSegundos()));
    }
  }

  /**
   * Chave do usuário a partir do upn já validado, em hash SHA-256. Valor nunca vai para o log em claro.
   */
  static Optional<String> chaveUsuarioValidado(Object upn) {
    if (!(upn instanceof String s) || s.isBlank()) {
      return Optional.empty();
    }
    return Optional.of("usr:" + sha256(s.trim()));
  }

  /** Só para testes unitários: injeta contador e limite sem Config. */
  void usarContadorParaTeste(RateLimitContador contador, int limite, long janelaSegundos) {
    this.estado = new Estado(contador, limite, janelaSegundos);
  }

  private Estado estado() {
    Estado e = estado;
    if (e == null) {
      synchronized (this) {
        e = estado;
        if (e == null) {
          Config config = ConfigProvider.getConfig();
          long janela = config.getOptionalValue("gateway.rate-limit.janela-segundos", Long.class).orElse(60L);
          long max = config.getOptionalValue("gateway.rate-limit.max-entradas", Long.class).orElse(10_000L);
          int limite = config.getOptionalValue(PROP_LIMITE, Integer.class).orElse(LIMITE_USUARIO_PADRAO);
          e = new Estado(new RateLimitContador(max, Duration.ofSeconds(janela)), limite, janela);
          estado = e;
        }
      }
    }
    return e;
  }

  private static String normalizar(String path) {
    if (path == null) {
      return null;
    }
    String p = path;
    while (p.startsWith("/")) {
      p = p.substring(1);
    }
    while (p.endsWith("/")) {
      p = p.substring(0, p.length() - 1);
    }
    return p;
  }

  private static String sha256(String v) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(v.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException ex) {
      throw new IllegalStateException(ex);
    }
  }
}
