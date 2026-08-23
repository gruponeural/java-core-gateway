package br.com.gruponeural.core.gateway.security;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class SessaoGatewayValidator {

  @ConfigProperty(name = "app.sessao.url")
  String sessaoUrl;

  @ConfigProperty(name = "gateway.identity.query-param", defaultValue = "idUsuario")
  String identityQueryParam;

  @ConfigProperty(name = "gateway.sessao-validation.connect-timeout", defaultValue = "10000")
  int sessaoValidationConnectTimeoutMs;

  @ConfigProperty(name = "gateway.sessao-validation.read-timeout", defaultValue = "60000")
  int sessaoValidationReadTimeoutMs;

  @Inject
  SessaoGatewayCache sessaoGatewayCache;

  public boolean sessaoAtiva(String idSessao, String identityId) {
    Boolean cached = sessaoGatewayCache.get(idSessao, identityId);
    if (cached != null) {
      return cached;
    }

    boolean ativa = validarRemoto(idSessao, identityId);
    sessaoGatewayCache.put(idSessao, identityId, ativa);
    return ativa;
  }

  private boolean validarRemoto(String idSessao, String identityId) {
    try {
      String url = sessaoUrl.replaceAll("/$", "")
          + "/v1/validar/"
          + idSessao
          + "?"
          + identityQueryParam
          + "="
          + identityId;

      HttpClient client = HttpClient.newBuilder()
          .connectTimeout(Duration.ofMillis(sessaoValidationConnectTimeoutMs))
          .build();

      HttpRequest request = HttpRequest.newBuilder()
          .uri(URI.create(url))
          .timeout(Duration.ofMillis(sessaoValidationReadTimeoutMs))
          .GET()
          .build();

      HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
      return response.statusCode() == 200 && "true".equalsIgnoreCase(response.body().trim());
    } catch (Exception e) {
      throw new SecurityException("Não foi possível validar a sessão.", e);
    }
  }

}
