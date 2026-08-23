package br.com.gruponeural.core.gateway.route;

/**
 * Rota registrada com serviço, destino base e definição do path.
 */
public record RegisteredRoute(
    String servico,
    String urlDestino,
    RoutePath path,
    boolean resolveBffUrlAtRuntime
) {

  public RegisteredRoute(String servico, String urlDestino, RoutePath path) {
    this(servico, urlDestino, path, false);
  }

  public String resolveDestino(String pathSuffix) {
    String destino = path.getDestino();
    if (!path.isMatchOnUriPrefix()) {
      return destino;
    }

    String origem = path.getOrigem();
    if (pathSuffix.equals(origem)) {
      return destino;
    }

    String prefix = origem + "/";
    if (pathSuffix.startsWith(prefix)) {
      String tail = pathSuffix.substring(prefix.length());
      if (!tail.isEmpty()) {
        return destino.replaceAll("/$", "") + "/" + tail;
      }
    }

    return destino;
  }

  public String resolveBaseUrl(GatewayRouteRegistry registry) {
    if (resolveBffUrlAtRuntime) {
      return registry.resolveBffUrl();
    }
    return urlDestino;
  }

}
