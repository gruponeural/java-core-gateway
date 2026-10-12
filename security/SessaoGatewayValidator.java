package br.com.gruponeural.core.gateway.security;

import java.io.IOException;
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
    // Não cachear negativo: login faz upsert no mesmo id por dispositivo; um false
    // stale (ex.: pós-sair) bloquearia o JWT novo por todo o TTL enquanto renovar ainda passa.
    if (ativa) {
      sessaoGatewayCache.put(idSessao, identityId, true);
    } else {
      sessaoGatewayCache.invalidate(idSessao, identityId);
    }
    return ativa;
  }

  /** Resposta mínima do serviço de sessão (status e corpo). */
  record RespostaSessao(int status, String corpo) {
  }

  private boolean validarRemoto(String idSessao, String identityId) {
    String url = sessaoUrl.replaceAll("/$", "")
        + "/v1/validar/"
        + idSessao
        + "?"
        + identityQueryParam
        + "="
        + identityId;

    RespostaSessao resposta;
    try {
      resposta = chamarSessao(url);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new SessaoIndisponivelException("Validação da sessão interrompida.", e);
    } catch (IOException | RuntimeException e) {
      // Timeout, conexão recusada ou falha de rede: infraestrutura, não sessão inválida.
      throw new SessaoIndisponivelException("Serviço de sessão indisponível.", e);
    }

    if (resposta.status() >= 500) {
      throw new SessaoIndisponivelException("Serviço de sessão respondeu " + resposta.status() + ".");
    }
    String corpo = resposta.corpo() == null ? "" : resposta.corpo().trim();
    return resposta.status() == 200 && "true".equalsIgnoreCase(corpo);
  }

  private volatile HttpClient httpClient;

  /** HttpClient único (thread-safe), criado na primeira chamada com o connect-timeout configurado. */
  HttpClient httpClient() {
    HttpClient atual = httpClient;
    if (atual == null) {
      synchronized (this) {
        atual = httpClient;
        if (atual == null) {
          atual = HttpClient.newBuilder()
              .connectTimeout(Duration.ofMillis(sessaoValidationConnectTimeoutMs))
              .build();
          httpClient = atual;
        }
      }
    }
    return atual;
  }

  RespostaSessao chamarSessao(String url) throws IOException, InterruptedException {
    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(url))
        .timeout(Duration.ofMillis(sessaoValidationReadTimeoutMs))
        .GET()
        .build();

    HttpResponse<String> response = httpClient().send(request, HttpResponse.BodyHandlers.ofString());
    return new RespostaSessao(response.statusCode(), response.body());
  }

}
