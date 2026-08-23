package br.com.gruponeural.core.gateway.filter;

import java.io.IOException;
import java.util.UUID;

import org.jboss.logging.Logger;
import org.jboss.logging.MDC;

import br.com.gruponeural.core.gateway.route.GatewayRouteRegistry;
import br.com.gruponeural.core.gateway.route.RegisteredRoute;
import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.ext.Provider;

@Provider
@Priority(Priorities.AUTHENTICATION - 50)
public class CorrelationIdFilter implements ContainerRequestFilter, ContainerResponseFilter {

  public static final String CORRELATION_HEADER = "X-Correlation-ID";
  public static final String CORRELATION_RECEIVED_PROPERTY = "gateway.corrIdRecebido";

  private static final Logger LOG = Logger.getLogger(CorrelationIdFilter.class);

  @Override
  public void filter(ContainerRequestContext requestContext) throws IOException {
    String corrId = requestContext.getHeaderString(CORRELATION_HEADER);
    boolean corrIdRecebido = corrId != null && !corrId.isBlank();
    if (!corrIdRecebido) {
      corrId = UUID.randomUUID().toString().substring(0, 8);
    }
    requestContext.getHeaders().putSingle(CORRELATION_HEADER, corrId);
    requestContext.setProperty(CORRELATION_RECEIVED_PROPERTY, corrIdRecebido);
    MDC.put("correlationId", corrId);
    org.slf4j.MDC.put("correlationId", corrId);

    LOG.infof(
        "🧭 [CORRELATION] X-Correlation-ID=%s | recebido=%s",
        corrId,
        corrIdRecebido);
  }

  @Override
  public void filter(
      ContainerRequestContext requestContext,
      ContainerResponseContext responseContext) throws IOException {
    MDC.remove("correlationId");
    org.slf4j.MDC.remove("correlationId");
  }

  static String resolveRequestPath(ContainerRequestContext requestContext) {
    UriInfo uriInfo = requestContext.getUriInfo();
    String path = uriInfo.getPath();
    if (path == null) {
      return "";
    }
    return path.startsWith("/") ? path : "/" + path;
  }

  static RegisteredRoute matchRoute(GatewayRouteRegistry registry, ContainerRequestContext requestContext) {
    UriInfo uriInfo = requestContext.getUriInfo();
    String path = uriInfo.getPath();
    if (path == null || path.isBlank()) {
      return null;
    }

    String normalized = path.startsWith("/") ? path.substring(1) : path;
    int slash = normalized.indexOf('/');
    if (slash < 0) {
      return null;
    }

    String servico = normalized.substring(0, slash);
    String pathSuffix = normalized.substring(slash + 1);
    return registry.match(servico, requestContext.getMethod(), pathSuffix).orElse(null);
  }

}
