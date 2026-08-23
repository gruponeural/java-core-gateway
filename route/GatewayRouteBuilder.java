package br.com.gruponeural.core.gateway.route;

/**
 * DSL fluente usada pelos {@link GatewayRouteContributor} para registrar rotas.
 */
public class GatewayRouteBuilder {

  private final GatewayRouteRegistry registry;
  private String servico;
  private String urlDestino;
  private boolean resolveBffUrlAtRuntime;

  GatewayRouteBuilder(GatewayRouteRegistry registry) {
    this.registry = registry;
  }

  public GatewayRouteBuilder servico(String nomeServico) {
    this.servico = nomeServico.toLowerCase();
    return this;
  }

  public GatewayRouteBuilder urlDestino(String url) {
    this.urlDestino = url;
    this.resolveBffUrlAtRuntime = false;
    return this;
  }

  public GatewayRouteBuilder urlDestinoBff() {
    this.urlDestino = registry.resolveBffUrl();
    this.resolveBffUrlAtRuntime = true;
    return this;
  }

  public GatewayRouteBuilder rota(RoutePath path) {
    if (servico == null || servico.isBlank()) {
      throw new IllegalStateException("servico() deve ser chamado antes de rota()");
    }
    if (urlDestino == null || urlDestino.isBlank()) {
      throw new IllegalStateException("urlDestino() ou urlDestinoBff() deve ser chamado antes de rota()");
    }
    registry.register(servico, urlDestino, path, resolveBffUrlAtRuntime);
    return this;
  }

}
