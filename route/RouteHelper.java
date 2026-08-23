package br.com.gruponeural.core.gateway.route;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import br.com.gruponeural.core.geral.util.JsonUtil;

public class RouteHelper {

  private RouteHelper() {
  }

  public static String mascararDadosSensiveis(String json) {
    if (json == null || json.isEmpty()) {
      return json;
    }

    try {
      String regex = "(?i)\"(senha|password|token|secret|tokenAcesso)\"\\s*:\\s*\"[^\"]+\"";

      return json.replaceAll(regex, "\"$1\":\"********\"");
    } catch (Exception e) {
      return "[ERRO AO MASCARAR DADOS SENSÍVEIS]";
    }
  }

  public static byte[] prepararBodyBinarioParaProxy(byte[] bodyBytes) {
    return bodyBytes;
  }

  /**
   * Converte texto para {@code byte[]} e força {@code application/json} para o BFF Quarkus aceitar.
   */
  public static byte[] prepararBodyJsonParaProxy(String text) {
    if (text == null) {
      return new byte[0];
    }
    return text.getBytes(StandardCharsets.UTF_8);
  }

  public static String bodyRespostaComoTexto(Object body) throws IOException {
    if (body == null) {
      return null;
    }
    if (body instanceof String text) {
      return text;
    }
    if (body instanceof byte[] bytes) {
      return new String(bytes, StandardCharsets.UTF_8);
    }
    if (body instanceof InputStream inputStream) {
      return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
    }
    try {
      return JsonUtil.getMapper().writeValueAsString(body);
    } catch (Exception e) {
      return body.toString();
    }
  }

  public static boolean isRespostaBinaria(String contentType) {
    if (contentType == null || contentType.isBlank()) {
      return false;
    }
    return contentType.matches("(?i).*(image/|application/octet-stream).*");
  }

}
