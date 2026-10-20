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
    if (exception instanceof br.com.gruponeural.core.gateway.security.SessaoIndisponivelException indisponivel) {
      return new GatewaySessaoIndisponivelExceptionMapper().toResponse(indisponivel);
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

    // Só a classe e o status: a mensagem e a stack podem trazer token, URL ou dado do cliente.
    LOG.errorf("❌ [ERRO NO GATEWAY] %s. Status: 500", exception.getClass().getSimpleName());

    return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
        .type(MediaType.APPLICATION_JSON)
        .entity(body)
        .build();
  }

}
