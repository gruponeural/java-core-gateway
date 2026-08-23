package br.com.gruponeural.core.gateway.exception;

import org.jboss.logging.Logger;

import jakarta.annotation.Priority;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

@Provider
@Priority(5000)
public class GatewayUnhandledExceptionMapper implements ExceptionMapper<Exception> {

  private static final Logger LOG = Logger.getLogger(GatewayUnhandledExceptionMapper.class);

  @Override
  public Response toResponse(Exception exception) {
    if (exception instanceof WebApplicationException webApplicationException) {
      return webApplicationException.getResponse();
    }
    if (exception instanceof SecurityException securityException) {
      return new GatewaySecurityExceptionMapper().toResponse(securityException);
    }

    String correlationId = org.slf4j.MDC.get("correlationId");
    if (correlationId == null) {
      correlationId = "";
    }

    String body = """
        {
            "id": "%s",
            "mensagemTipo": "falha",
            "mensagemTitulo": "Falha na comunicação com o servidor.",
            "mensagemDetalhe": "Por favor, tente novamente mais tarde."
        }
        """.formatted(correlationId);

    LOG.errorf(exception, "❌ [ERRO NO GATEWAY] Causa: %s", exception.getMessage());
    LOG.info("🔙 [RESPOSTA] Status: 500");
    LOG.infof("📦 [BODY RESPOSTA]: %s", body);

    return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
        .type(MediaType.APPLICATION_JSON)
        .entity(body)
        .build();
  }

}
