package br.com.gruponeural.core.gateway.exception;

import org.jboss.logging.Logger;

import br.com.gruponeural.core.gateway.security.SessaoIndisponivelException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

@Provider
public class GatewaySessaoIndisponivelExceptionMapper implements ExceptionMapper<SessaoIndisponivelException> {

  private static final Logger LOG = Logger.getLogger(GatewaySessaoIndisponivelExceptionMapper.class);

  static final String TITULO = "Estamos com instabilidade no momento. Tente novamente em instantes.";

  @Override
  public Response toResponse(SessaoIndisponivelException exception) {
    String correlationId = org.slf4j.MDC.get("correlationId");
    if (correlationId == null) {
      correlationId = "";
    }

    String body = """
        {
            "id": "%s",
            "mensagemTipo": "falha",
            "mensagemTitulo": "%s",
            "mensagemDetalhe": ""
        }
        """.formatted(correlationId, TITULO);

    LOG.errorf(exception, "❌ [SESSAO] Serviço de sessão indisponível: %s", exception.getMessage());
    LOG.info("🔙 [RESPOSTA] Status: 503");

    return Response.status(Response.Status.SERVICE_UNAVAILABLE)
        .type(MediaType.APPLICATION_JSON)
        .entity(body)
        .build();
  }
}
