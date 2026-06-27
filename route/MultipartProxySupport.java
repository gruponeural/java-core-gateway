package br.com.gruponeural.core.gateway.route;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.UUID;

import org.apache.camel.Exchange;

/**
 * O consumer {@code platform-http} do Camel decompõe multipart: campos de texto viram headers
 * e o arquivo vira body binário. O BFF espera {@code multipart/form-data} completo — remontamos aqui.
 */
final class MultipartProxySupport {

    private static final Set<String> CAMPOS_TEXTO = Set.of("descricao", "medidas");

    private MultipartProxySupport() {
    }

    static void prepararProxyMultipart(Exchange exchange) throws IOException {
        var in = exchange.getIn();
        byte[] body = exchange.getContext().getTypeConverter().convertTo(byte[].class, in.getBody());
        if (body == null) {
            return;
        }

        if (iniciaComMultipart(body)) {
            in.setBody(body);
            in.setHeader(Exchange.CONTENT_LENGTH, body.length);
            limparHeadersInternos(in);
            return;
        }

        String descricao = in.getHeader("descricao", String.class);
        if (descricao == null) {
            for (String campo : CAMPOS_TEXTO) {
                String valor = in.getHeader(campo, String.class);
                if (valor != null && !valor.isBlank()) {
                    descricao = valor;
                    break;
                }
            }
        }

        String nomeArquivo = in.getHeader("fileName", String.class);
        if (nomeArquivo == null || nomeArquivo.isBlank()) {
            nomeArquivo = in.getHeader("filename", String.class);
        }
        if (nomeArquivo == null || nomeArquivo.isBlank()) {
            nomeArquivo = "imagem.webp";
        }

        String tipoArquivo = in.getHeader("fileContentType", String.class);
        if (tipoArquivo == null || tipoArquivo.isBlank()) {
            tipoArquivo = "application/octet-stream";
        }

        byte[] multipart = remontarMultipart(descricao, body, nomeArquivo, tipoArquivo);
        String boundary = extrairBoundary(multipart);
        in.setBody(multipart);
        in.setHeader(Exchange.CONTENT_TYPE, "multipart/form-data; boundary=" + boundary);
        in.setHeader(Exchange.CONTENT_LENGTH, multipart.length);
        limparHeadersInternos(in);
    }

    private static boolean iniciaComMultipart(byte[] body) {
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
        ByteArrayOutputStream out = new ByteArrayOutputStream();

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

    private static void limparHeadersInternos(org.apache.camel.Message in) {
        in.removeHeader("SubPath");
        in.removeHeader("TargetUrl");
        in.removeHeader(Exchange.TRANSFER_ENCODING);
        in.removeHeader("Host");
        in.removeHeader("Connection");
        in.removeHeader("descricao");
        in.removeHeader("file");
        in.removeHeader("fileName");
        in.removeHeader("filename");
        in.removeHeader("fileContentType");
        in.removeHeader("medidas");
    }

}
