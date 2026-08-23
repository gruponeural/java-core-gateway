package br.com.gruponeural.core.gateway.filter;

import java.io.IOException;

import org.jboss.logging.Logger;

import br.com.gruponeural.core.gateway.route.GatewayRouteRegistry;
import br.com.gruponeural.core.gateway.route.RegisteredRoute;
import br.com.gruponeural.core.gateway.security.JwtValidatorService;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;

@Provider
@Priority(Priorities.AUTHENTICATION + 10)
public class GatewayJwtAuthFilter implements ContainerRequestFilter {

  private static final Logger LOG = Logger.getLogger(GatewayJwtAuthFilter.class);

  @Inject
  JwtValidatorService jwtValidatorService;

  @Override
  public void filter(ContainerRequestContext requestContext) throws IOException {
    RegisteredRoute route = (RegisteredRoute) requestContext.getProperty(GatewayRouteRegistry.MATCHED_ROUTE_PROPERTY);
    if (route == null || !Boolean.TRUE.equals(route.path().getRequerAutenticacao())) {
      return;
    }

    LOG.info("🔐 [AUTH] Validando token JWT...");
    String identityId = jwtValidatorService.validar(requestContext.getHeaderString("Authorization"));
    if (identityId != null && !identityId.isBlank()) {
      requestContext.getHeaders().putSingle(jwtValidatorService.getIdentityHeader(), identityId);
    }
    requestContext.getHeaders().remove("Authorization");
  }

}
