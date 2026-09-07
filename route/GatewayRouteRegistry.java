package br.com.gruponeural.core.gateway.route;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

@ApplicationScoped
public class GatewayRouteRegistry {

  public static final String MATCHED_ROUTE_PROPERTY = "gateway.matched-route";

  @ConfigProperty(name = "gateway.bff.url")
  String gatewayBffUrl;

  @Inject
  Instance<GatewayRouteContributor> contributors;

  private final List<RegisteredRoute> routes = new ArrayList<>();

  void onStart(@Observes StartupEvent event) {
    GatewayRouteBuilder builder = new GatewayRouteBuilder(this);
    contributors.forEach(contributor -> contributor.contribute(builder));
  }

  public void register(String servico, String urlDestino, RoutePath path) {
    register(servico, urlDestino, path, false);
  }

  public void register(String servico, String urlDestino, RoutePath path, boolean resolveBffUrlAtRuntime) {
    routes.add(new RegisteredRoute(servico.toLowerCase(), urlDestino, path, resolveBffUrlAtRuntime));
  }

  public String resolveBffUrl() {
    String base = gatewayBffUrl;
    try {
      var fromFile = br.com.gruponeural.core.geral.ops.RotasArquivo.bffUrl();
      if (fromFile.isPresent()) {
        base = fromFile.get();
      }
    } catch (Throwable ignored) {
      /* core/geral sem RotasArquivo em builds antigos */
    }
    if (base == null || base.isBlank()) {
      base = ConfigProvider.getConfig().getValue("gateway.bff.url", String.class);
    }
    return base;
  }

  /**
   * Localiza rota pelo path completo após a base do gateway (ex.: {@code aproveitemais/pedido/listar}).
   * Usa o nome de serviço registrado mais longo que for prefixo do path (serviços com {@code /}).
   */
  public Optional<RegisteredRoute> matchFullPath(String method, String fullPath) {
    if (method == null || fullPath == null || fullPath.isBlank()) {
      return Optional.empty();
    }
    String normalized = fullPath.startsWith("/") ? fullPath.substring(1) : fullPath;
    if (normalized.isBlank()) {
      return Optional.empty();
    }

    String bestServico = null;
    for (RegisteredRoute route : routes) {
      String servico = route.servico();
      if (normalized.equals(servico) || normalized.startsWith(servico + "/")) {
        if (bestServico == null || servico.length() > bestServico.length()) {
          bestServico = servico;
        }
      }
    }
    if (bestServico == null) {
      int slash = normalized.indexOf('/');
      if (slash < 0) {
        return Optional.empty();
      }
      bestServico = normalized.substring(0, slash);
    }

    String pathSuffix = normalized.substring(bestServico.length());
    if (pathSuffix.startsWith("/")) {
      pathSuffix = pathSuffix.substring(1);
    }
    if (pathSuffix.isBlank()) {
      return Optional.empty();
    }
    return match(bestServico, method, pathSuffix);
  }

  /**
   * Localiza rota por serviço, método HTTP e sufixo após o serviço (ex.: {@code listar}, {@code obter/uuid}).
   */
  public Optional<RegisteredRoute> match(String servico, String method, String pathSuffix) {
    if (servico == null || method == null || pathSuffix == null) {
      return Optional.empty();
    }

    String normalizedServico = servico.toLowerCase();
    String normalizedMethod = method.toUpperCase();
    String normalizedPath = pathSuffix.startsWith("/") ? pathSuffix.substring(1) : pathSuffix;

    Optional<RegisteredRoute> exact = routes.stream()
        .filter(route -> route.servico().equals(normalizedServico))
        .filter(route -> route.path().getMetodo().equalsIgnoreCase(normalizedMethod))
        .filter(route -> !route.path().isMatchOnUriPrefix())
        .filter(route -> route.path().getOrigem().equals(normalizedPath))
        .findFirst();
    if (exact.isPresent()) {
      return exact;
    }

    return routes.stream()
        .filter(route -> route.servico().equals(normalizedServico))
        .filter(route -> route.path().getMetodo().equalsIgnoreCase(normalizedMethod))
        .filter(route -> route.path().isMatchOnUriPrefix())
        .filter(route -> matchesPrefix(route.path().getOrigem(), normalizedPath))
        .findFirst();
  }

  private static boolean matchesPrefix(String origem, String pathSuffix) {
    if (pathSuffix.equals(origem)) {
      return true;
    }
    return pathSuffix.startsWith(origem + "/");
  }

  public List<RegisteredRoute> getRoutes() {
    return List.copyOf(routes);
  }

}
