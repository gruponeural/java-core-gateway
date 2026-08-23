package br.com.gruponeural.core.gateway.route;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * O consumer HTTP decompõe multipart: campos de texto viram headers e o arquivo vira body binário.
 * O BFF espera {@code multipart/form-data} completo — remontamos aqui quando necessário.
 */
public final class MultipartProxySupport {

  private static final Set<String> CAMPOS_TEXTO = Set.of("descricao", "medidas");

  private MultipartProxySupport() {
  }

  public static byte[] prepararProxyMultipart(byte[] body, String contentType, Map<String, String> headers)
      throws IOException {
    if (body == null) {
      return null;
    }

    if (iniciaComMultipart(body)) {
      return body;
    }

    String descricao = headers.get("descricao");
    if (descricao == null) {
      for (String campo : CAMPOS_TEXTO) {
        String valor = headers.get(campo);
        if (valor != null && !valor.isBlank()) {
          descricao = valor;
          break;
        }
      }
    }

    String nomeArquivo = headers.get("fileName");
    if (nomeArquivo == null || nomeArquivo.isBlank()) {
      nomeArquivo = headers.get("filename");
    }
    if (nomeArquivo == null || nomeArquivo.isBlank()) {
      nomeArquivo = "imagem.webp";
    }

    String tipoArquivo = headers.get("fileContentType");
    if (tipoArquivo == null || tipoArquivo.isBlank()) {
      tipoArquivo = contentType != null && !contentType.isBlank() ? contentType : "application/octet-stream";
    }

    return remontarMultipart(descricao, body, nomeArquivo, tipoArquivo);
  }

  public static String boundaryFromMultipart(byte[] multipart) {
    return extrairBoundary(multipart);
  }

  public static boolean iniciaComMultipart(byte[] body) {
    if (body.length < 2) {
      return false;
    }
    return body[0] == '-' && body[1] == '-';
  }

  private static byte[] remontarMultipart(
      String descricao,
      byte[] arquivo,
      String nomeArquivo,
      String tipoArquivo) throws IOException {

    String boundary = "----Gruponeural" + UUID.randomUUID().toString().replace("-", "");
    java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();

    if (descricao != null && !descricao.isBlank()) {
      out.write(("--" + boundary + "\r\n").getBytes(StandardCharsets.UTF_8));
      out.write("Content-Disposition: form-data; name=\"descricao\"\r\n\r\n".getBytes(StandardCharsets.UTF_8));
      out.write(descricao.getBytes(StandardCharsets.UTF_8));
      out.write("\r\n".getBytes(StandardCharsets.UTF_8));
    }

    out.write(("--" + boundary + "\r\n").getBytes(StandardCharsets.UTF_8));
    out.write(("Content-Disposition: form-data; name=\"file\"; filename=\"" + nomeArquivo + "\"\r\n")
        .getBytes(StandardCharsets.UTF_8));
    out.write(("Content-Type: " + tipoArquivo + "\r\n\r\n").getBytes(StandardCharsets.UTF_8));
    out.write(arquivo);
    out.write(("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
    return out.toByteArray();
  }

  private static String extrairBoundary(byte[] multipart) {
    int fim = 0;
    while (fim < multipart.length && multipart[fim] != '\r' && multipart[fim] != '\n') {
      fim++;
    }
    String primeiraLinha = new String(multipart, 0, fim, StandardCharsets.UTF_8);
    return primeiraLinha.startsWith("--") ? primeiraLinha.substring(2) : primeiraLinha;
  }

}
