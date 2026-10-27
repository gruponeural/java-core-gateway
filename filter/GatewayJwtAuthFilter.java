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

  private static final String[] HEADERS_IDENTIDADE = { "X-Id-Pessoa", "X-Id-Usuario" };

  /** Upn do JWT já validado (assinatura + sessão). Usado pelo rate limit pós-auth; nunca confiar no cliente. */
  public static final String UPN_VALIDADO_PROPERTY = "gateway.jwt.upn-validado";

  @Inject
  JwtValidatorService jwtValidatorService;

  @Override
  public void filter(ContainerRequestContext requestContext) throws IOException {
    // Identidade só pode vir do token validado aqui; nunca do cliente.
    for (String header : HEADERS_IDENTIDADE) {
      requestContext.getHeaders().remove(header);
    }
    requestContext.getHeaders().remove(jwtValidatorService.getIdentityHeader());

    RegisteredRoute route = (RegisteredRoute) requestContext.getProperty(GatewayRouteRegistry.MATCHED_ROUTE_PROPERTY);
    if (route != null && route.path().getDestino() != null && route.path().getDestino().endsWith("sessao/sair")) {
      jwtValidatorService.invalidarSessaoEmCache(requestContext.getHeaderString("Authorization"));
    }
    if (route == null || !Boolean.TRUE.equals(route.path().getRequerAutenticacao())) {
      return;
    }

    LOG.info("🔐 [AUTH] Validando token JWT...");
    String identityId = jwtValidatorService.validar(requestContext.getHeaderString("Authorization"));
    requestContext.setProperty(UPN_VALIDADO_PROPERTY, identityId);
    requestContext.getHeaders().putSingle(jwtValidatorService.getIdentityHeader(), identityId);
    requestContext.getHeaders().remove("Authorization");
  }

}
