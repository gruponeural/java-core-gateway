package br.com.gruponeural.core.gateway.filter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.logging.Logger;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;

/**
 * Rate limit por usuário de {@code produto/favorito/obter} e {@code produto/favorito/salvar}, depois da
 * autenticação. Usa o upn já validado por {@link GatewayJwtAuthFilter}, em hash, com contador por rota.
 * Properties: {@code gateway.rate-limit.favorito-salvar.limite} (default 30) e
 * {@code gateway.rate-limit.favorito-obter.limite} (default 60).
 */
@Provider
@Priority(Priorities.AUTHENTICATION + 20)
public class RateLimitFavoritoUsuarioFilter implements ContainerRequestFilter {

  private static final Logger LOG = Logger.getLogger(RateLimitFavoritoUsuarioFilter.class);

  static final String PATH_SALVAR = "produto/favorito/salvar";
  static final String PATH_OBTER = "produto/favorito/obter";
  static final int LIMITE_SALVAR_PADRAO = 30;
  static final int LIMITE_OBTER_PADRAO = 60;
  static final String PROP_SALVAR = "gateway.rate-limit.favorito-salvar.limite";
  static final String PROP_OBTER = "gateway.rate-limit.favorito-obter.limite";

  private volatile Estado estado;

  private record Estado(RateLimitContador contador, Map<String, Integer> limites, long janelaSegundos) {
  }

  @Override
  public void filter(ContainerRequestContext requestContext) throws IOException {
    if (!"POST".equalsIgnoreCase(requestContext.getMethod())) {
      return;
    }
    String path = normalizar(requestContext.getUriInfo().getPath());
    if (!PATH_SALVAR.equals(path) && !PATH_OBTER.equals(path)) {
      return;
    }
    var chave = RateLimitBairroUsuarioFilter.chaveUsuarioValidado(
        requestContext.getProperty(GatewayJwtAuthFilter.UPN_VALIDADO_PROPERTY));
    if (chave.isEmpty()) {
      return;
    }
    Estado e = estado();
    if (!e.contador().permitir(path + "|" + chave.get(), e.limites().get(path))) {
      LOG.warnf("Rate limit favorito (usuario) excedido em %s", path);
      String correlationId = org.slf4j.MDC.get("correlationId");
      requestContext.abortWith(RateLimitFilter.resposta429(correlationId, e.janelaSegundos()));
    }
  }

  /** Só para testes unitários: injeta contador e limites sem Config. */
  void usarContadorParaTeste(RateLimitContador contador, int limiteSalvar, int limiteObter, long janelaSegundos) {
    this.estado = new Estado(contador, Map.of(PATH_SALVAR, limiteSalvar, PATH_OBTER, limiteObter), janelaSegundos);
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
          int salvar = config.getOptionalValue(PROP_SALVAR, Integer.class).orElse(LIMITE_SALVAR_PADRAO);
          int obter = config.getOptionalValue(PROP_OBTER, Integer.class).orElse(LIMITE_OBTER_PADRAO);
          e = new Estado(new RateLimitContador(max, Duration.ofSeconds(janela)),
              Map.of(PATH_SALVAR, salvar, PATH_OBTER, obter), janela);
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
}
