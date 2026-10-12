package br.com.gruponeural.core.gateway.security;

import java.util.Set;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;

import br.com.gruponeural.core.geral.constant.SessaoConst;
import io.smallrye.jwt.auth.principal.JWTParser;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class JwtValidatorService {

  private static final Logger LOG = Logger.getLogger(JwtValidatorService.class);

  @ConfigProperty(name = "gateway.identity.header", defaultValue = "X-Id-Usuario")
  String identityHeader;

  @Inject
  JWTParser jwtParser;

  @Inject
  SessaoGatewayValidator sessaoGatewayValidator;

  public String validar(String authHeader) {
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      throw new SessaoExpiradaException("Token JWT ausente ou inválido.");
    }

    String token = authHeader.substring("Bearer ".length());

    JsonWebToken jwt;
    try {
      jwt = jwtParser.parse(token);
    } catch (Exception e) {
      throw new SessaoExpiradaException("Token JWT ausente ou inválido.", e);
    }

    Set<String> groups = jwt.getGroups();
    if (!groups.contains(SessaoConst.SESSAO_USUARIO.getValor())) {
      throw new SessaoExpiradaException("Usuário não autorizado.");
    }

    String identityId = jwt.getClaim("upn");
    if (identityId == null || identityId.isBlank()) {
      throw new SessaoExpiradaException("Token JWT ausente ou inválido.");
    }

    String idSessao = jwt.getClaim("sid");
    if (idSessao == null || idSessao.isBlank()) {
      throw new SessaoExpiradaException("Sessão não autorizada.");
    }
    if (!sessaoGatewayValidator.sessaoAtiva(idSessao, identityId)) {
      throw new SessaoExpiradaException("Sessão não autorizada.");
    }

    return identityId;
  }

  @Inject
  SessaoGatewayCache sessaoGatewayCache;

  /** Logout: tira a sessão do cache para o token receber 401 na hora, sem esperar o TTL. */
  public void invalidarSessaoEmCache(String authHeader) {
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      return;
    }
    try {
      JsonWebToken jwt = jwtParser.parse(authHeader.substring("Bearer ".length()));
      String upn = jwt.getClaim("upn");
      String sid = jwt.getClaim("sid");
      if (upn != null && sid != null) {
        sessaoGatewayCache.invalidate(sid, upn);
      }
    } catch (Exception e) {
      // Token ilegível não tem o que invalidar. Só a classe do erro vai para o log:
      // a mensagem/stack do parser pode conter o token.
      LOG.warnf("⚠️ [SESSAO] Logout sem invalidar o cache: token não pôde ser lido (%s).", e.getClass().getSimpleName());
    }
  }

  public String getIdentityHeader() {
    return identityHeader;
  }

}
