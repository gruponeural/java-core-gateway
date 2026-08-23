package br.com.gruponeural.core.gateway.security;

import java.util.Set;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;

import br.com.gruponeural.core.geral.constant.SessaoConst;
import io.smallrye.jwt.auth.principal.JWTParser;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class JwtValidatorService {

  @ConfigProperty(name = "gateway.identity.header", defaultValue = "X-Id-Usuario")
  String identityHeader;

  @Inject
  JWTParser jwtParser;

  @Inject
  SessaoGatewayValidator sessaoGatewayValidator;

  public String validar(String authHeader) {
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      throw new SecurityException("Token JWT ausente ou inválido.");
    }

    String token = authHeader.substring("Bearer ".length());

    JsonWebToken jwt;
    try {
      jwt = jwtParser.parse(token);
    } catch (Exception e) {
      throw new SecurityException("Token JWT ausente ou inválido.", e);
    }

    Set<String> groups = jwt.getGroups();
    if (!groups.contains(SessaoConst.SESSAO_USUARIO.getValor())) {
      throw new SecurityException("Usuário não autorizado.");
    }

    String identityId = jwt.getClaim("upn");
    if (identityId == null || identityId.isBlank()) {
      return null;
    }

    String idSessao = jwt.getClaim("sid");
    if (idSessao != null && !idSessao.isBlank()) {
      if (!sessaoGatewayValidator.sessaoAtiva(idSessao, identityId)) {
        throw new SecurityException("Sessão não autorizada.");
      }
    }

    return identityId;
  }

  public String getIdentityHeader() {
    return identityHeader;
  }

}
