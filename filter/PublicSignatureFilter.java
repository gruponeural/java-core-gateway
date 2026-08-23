package br.com.gruponeural.core.gateway.filter;

import java.io.IOException;

import org.jboss.logging.Logger;

import br.com.gruponeural.core.gateway.route.GatewayRouteRegistry;
import br.com.gruponeural.core.gateway.route.RegisteredRoute;
import br.com.gruponeural.core.gateway.security.PublicValidatorService;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;

@Provider
@Priority(Priorities.AUTHENTICATION)
public class PublicSignatureFilter implements ContainerRequestFilter {

  private static final Logger LOG = Logger.getLogger(PublicSignatureFilter.class);

  @Inject
  PublicValidatorService publicValidatorService;

  @Inject
  GatewayRouteRegistry routeRegistry;

  @Override
  public void filter(ContainerRequestContext requestContext) throws IOException {
    RegisteredRoute route = CorrelationIdFilter.matchRoute(routeRegistry, requestContext);
    if (route == null) {
      return;
    }

    requestContext.setProperty(GatewayRouteRegistry.MATCHED_ROUTE_PROPERTY, route);

    String requestPath = CorrelationIdFilter.resolveRequestPath(requestContext);
    LOG.infof("📥 [ENTRADA] Método: %s | Path: %s", requestContext.getMethod(), requestPath);
    LOG.info("🔒 [AUTH] Validando X-Signature e X-Timestamp...");

    publicValidatorService.validar(
        requestPath,
        requestContext.getHeaderString("X-Signature"),
        requestContext.getHeaderString("X-Timestamp"));

    requestContext.getHeaders().remove("X-Signature");
    requestContext.getHeaders().remove("X-Timestamp");
  }

}
