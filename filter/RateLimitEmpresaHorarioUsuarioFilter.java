package br.com.gruponeural.core.gateway.filter;

import java.io.IOException;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.logging.Logger;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;

/**
 * Rate limit por usuário (CS-SEG-09) das escritas de horário, data especial e preferência
 * de notificação, depois da autenticação. As quatro rotas compartilham 30 tentativas na janela.
 * Usa o upn já validado por {@link GatewayJwtAuthFilter} (propriedade do request), nunca o JWT cru.
 * Properties: {@code gateway.rate-limit.empresa-horario.limite} (default 30) e
 * {@code gateway.rate-limit.janela-segundos} (default 60).
 */
@Provider
@Priority(Priorities.AUTHENTICATION + 20)
public class RateLimitEmpresaHorarioUsuarioFilter implements ContainerRequestFilter {

  private static final Logger LOG = Logger.getLogger(RateLimitEmpresaHorarioUsuarioFilter.class);

  static final Set<String> PATHS = Set.of(
      "empresa/horario/salvar",
      "empresa/data-especial/salvar",
      "empresa/data-especial/remover",
      "notificacao/preferencia/salvar");
  /** Chave única: as rotas acima contam juntas para o mesmo usuário. */
  static final String CHAVE_PREFIXO = "empresa-horario";
  static final int LIMITE_USUARIO_PADRAO = 30;
  static final String PROP_LIMITE = "gateway.rate-limit.empresa-horario.limite";

  private volatile Estado estado;

  private record Estado(RateLimitContador contador, int limite, long janelaSegundos) {
  }

  @Override
  public void filter(ContainerRequestContext requestContext) throws IOException {
    if (!"POST".equalsIgnoreCase(requestContext.getMethod())) {
      return;
    }
    String path = normalizar(requestContext.getUriInfo().getPath());
    if (!PATHS.contains(path)) {
      return;
    }
    Optional<String> chave = RateLimitBairroUsuarioFilter.chaveUsuarioValidado(
        requestContext.getProperty(GatewayJwtAuthFilter.UPN_VALIDADO_PROPERTY));
    if (chave.isEmpty()) {
      return;
    }
    Estado e = estado();
    if (!e.contador().permitir(CHAVE_PREFIXO + "|" + chave.get(), e.limite())) {
      LOG.warnf("Rate limit empresa-horario (usuario) excedido em %s", path);
      String correlationId = org.slf4j.MDC.get("correlationId");
      requestContext.abortWith(RateLimitFilter.resposta429(correlationId, e.janelaSegundos()));
    }
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
}
