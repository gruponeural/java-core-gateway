package br.com.gruponeural.core.gateway.exception;

import org.jboss.logging.Logger;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

@Provider
public class GatewaySecurityExceptionMapper implements ExceptionMapper<SecurityException> {

  private static final Logger LOG = Logger.getLogger(GatewaySecurityExceptionMapper.class);

  @Override
  public Response toResponse(SecurityException exception) {
    String correlationId = org.slf4j.MDC.get("correlationId");
    if (correlationId == null) {
      correlationId = "";
    }

    String body = """
        {
            "id": "%s",
            "mensagemTipo": "falha",
            "mensagemTitulo": "Acesso não autorizado.",
            "mensagemDetalhe": "Assinatura do aplicativo inválida ou expirada."
        }
        """.formatted(correlationId);

    LOG.warnf(exception, "⚠️ [SECURITY] Tentativa de acesso negada: %s", exception.getMessage());
    LOG.info("🔙 [RESPOSTA] Status: 401");
    LOG.infof("📦 [BODY RESPOSTA]: %s", body);

    return Response.status(Response.Status.UNAUTHORIZED)
        .type(MediaType.APPLICATION_JSON)
        .entity(body)
        .build();
  }

}
