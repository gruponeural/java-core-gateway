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

    String detalhe = detalheParaCliente(exception);
    String body = """
        {
            "id": "%s",
            "mensagemTipo": "falha",
            "mensagemTitulo": "Acesso não autorizado.",
            "mensagemDetalhe": "%s"
        }
        """.formatted(correlationId, detalhe);

    LOG.warnf(exception, "⚠️ [SECURITY] Tentativa de acesso negada: %s", exception.getMessage());
    LOG.info("🔙 [RESPOSTA] Status: 401");
    LOG.infof("📦 [BODY RESPOSTA]: %s", body);

    return Response.status(Response.Status.UNAUTHORIZED)
        .type(MediaType.APPLICATION_JSON)
        .entity(body)
        .build();
  }

  /**
   * Evita mascarar falha de sessão/JWT como “assinatura inválida”.
   * Escapa aspas para o JSON embutido no mapper.
   */
  private static String detalheParaCliente(SecurityException exception) {
    String msg = exception.getMessage();
    if (msg == null || msg.isBlank()) {
      return "Assinatura do aplicativo inválida ou expirada.";
    }
    String lower = msg.toLowerCase();
    if (lower.contains("assinatura")) {
      return "Assinatura do aplicativo inválida ou expirada.";
    }
    if (lower.contains("sessão") || lower.contains("sessao") || lower.contains("token") || lower.contains("jwt")
        || lower.contains("não autorizado") || lower.contains("nao autorizado")) {
      return msg.replace("\\", "\\\\").replace("\"", "\\\"");
    }
    return "Assinatura do aplicativo inválida ou expirada.";
  }

}
