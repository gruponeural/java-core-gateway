package br.com.gruponeural.core.gateway.filter;

import java.io.IOException;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.logging.Logger;

import br.com.gruponeural.core.gateway.route.GatewayRouteRegistry;
import br.com.gruponeural.core.gateway.route.RegisteredRoute;
import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;

/**
 * Rate limit por usuário (CS-SEG-09) das escritas de horário, data especial e preferência
 * de notificação da Central de Controle, depois da autenticação. As quatro rotas da Central
 * compartilham a janela. Usa o upn já validado por {@link GatewayJwtAuthFilter} (propriedade
 * do request), nunca o JWT cru.
 * A decisão usa a rota já casada ({@link GatewayRouteRegistry#MATCHED_ROUTE_PROPERTY}):
 * {@code servico()} + {@code path().getOrigem()}, não o path cru.
 * Só limita quando {@code gateway.rate-limit.empresa-horario.limite} está definida.
 * Este core não tem default; a Central define o valor no {@code application.properties}.
 * Janela: {@code gateway.rate-limit.janela-segundos} (default 60).
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
  static final String PROP_LIMITE = "gateway.rate-limit.empresa-horario.limite";

  private volatile Estado estado;

  private record Estado(RateLimitContador contador, int limite, long janelaSegundos) {
    private static Estado desligado() {
      return new Estado(null, 0, 0);
    }

    private boolean ativo() {
      return contador != null;
    }
  }

  @Override
  public void filter(ContainerRequestContext requestContext) throws IOException {
    if (!"POST".equalsIgnoreCase(requestContext.getMethod())) {
      return;
    }
    String rota = rotaCanonica(requestContext);
    if (rota == null || !PATHS.contains(rota)) {
      return;
    }
    Optional<String> chave = RateLimitBairroUsuarioFilter.chaveUsuarioValidado(
        requestContext.getProperty(GatewayJwtAuthFilter.UPN_VALIDADO_PROPERTY));
    if (chave.isEmpty()) {
      return;
    }
    Estado e = estado();
    if (!e.ativo()) {
      return;
    }
    if (!e.contador().permitir(CHAVE_PREFIXO + "|" + chave.get(), e.limite())) {
      LOG.warnf("Rate limit empresa-horario (usuario) excedido em %s", rota);
      String correlationId = org.slf4j.MDC.get("correlationId");
      requestContext.abortWith(RateLimitFilter.resposta429(correlationId, e.janelaSegundos()));
    }
  }

  /** Serviço + origem da rota já casada pelo registry. {@code null} se não houver rota. */
  private static String rotaCanonica(ContainerRequestContext requestContext) {
    Object cru = requestContext.getProperty(GatewayRouteRegistry.MATCHED_ROUTE_PROPERTY);
    if (!(cru instanceof RegisteredRoute route) || route.path() == null) {
      return null;
    }
    String servico = route.servico();
    String origem = route.path().getOrigem();
    if (servico == null || origem == null) {
      return null;
    }
    return servico + "/" + origem;
  }

  /** Só para testes unitários: injeta contador e limite sem Config. */
  void usarContadorParaTeste(RateLimitContador contador, int limite, long janelaSegundos) {
    this.estado = new Estado(contador, limite, janelaSegundos);
  }

  /** Só para testes unitários: monta o estado a partir de um Config isolado. */
  void aplicarConfigParaTeste(Config config) {
    this.estado = montarEstado(config);
  }

  private Estado estado() {
    Estado e = estado;
    if (e == null) {
      synchronized (this) {
        e = estado;
        if (e == null) {
          e = montarEstado(ConfigProvider.getConfig());
          estado = e;
        }
      }
    }
    return e;
  }

  /**
   * Sem {@code gateway.rate-limit.empresa-horario.limite} o filtro fica desligado.
   * Não há limite padrão neste core.
   */
  private static Estado montarEstado(Config config) {
    Optional<Integer> limite = config.getOptionalValue(PROP_LIMITE, Integer.class);
    if (limite.isEmpty()) {
      return Estado.desligado();
    }
    long janela = config.getOptionalValue("gateway.rate-limit.janela-segundos", Long.class).orElse(60L);
    long max = config.getOptionalValue("gateway.rate-limit.max-entradas", Long.class).orElse(10_000L);
    return new Estado(new RateLimitContador(max, Duration.ofSeconds(janela)), limite.get(), janela);
  }
}
