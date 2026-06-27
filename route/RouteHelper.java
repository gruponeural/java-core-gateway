package br.com.gruponeural.core.gateway.route;

import java.io.IOException;
import java.io.InputStream;

import org.apache.camel.Exchange;

import io.vertx.core.buffer.Buffer;

public class RouteHelper {

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

    /**
     * Garante body binário (multipart) como {@code byte[]} com Content-Length coerente
     * antes do proxy HTTP — evita truncamento no BFF ("Connection terminated reading multipart data").
     */
    public static void prepararBodyBinarioParaProxy(Exchange exchange) throws IOException {
        var in = exchange.getIn();
        byte[] bodyBytes = exchange.getContext().getTypeConverter().convertTo(byte[].class, in.getBody());

        if (bodyBytes == null) {
            InputStream inputStream = in.getBody(InputStream.class);
            if (inputStream != null) {
                bodyBytes = inputStream.readAllBytes();
            }
        }

        if (bodyBytes == null) {
            Buffer buffer = in.getBody(Buffer.class);
            if (buffer != null) {
                bodyBytes = buffer.getBytes();
            }
        }

        if (bodyBytes == null) {
            return;
        }

        in.setBody(bodyBytes);
        in.setHeader(Exchange.CONTENT_LENGTH, bodyBytes.length);
        in.removeHeader(Exchange.TRANSFER_ENCODING);
        in.removeHeader("Host");
        in.removeHeader("Connection");
        in.removeHeader("Accept-Encoding");
        in.removeHeader("Content-Encoding");

        String contentType = in.getHeader(Exchange.CONTENT_TYPE, String.class);
        if (contentType == null || contentType.isBlank()) {
            contentType = in.getHeader("Content-Type", String.class);
        }
        if (contentType != null && !contentType.isBlank()) {
            in.setHeader(Exchange.CONTENT_TYPE, contentType);
        }

        String method = in.getHeader(Exchange.HTTP_METHOD, String.class);
        if (method == null || method.isBlank()) {
            method = in.getHeader("CamelHttpMethod", String.class);
        }
        if (method != null && !method.isBlank()) {
            in.setHeader(Exchange.HTTP_METHOD, method);
        }
    }

    /** Reaplica headers necessários ao BFF quando {@code copyHeaders=false} no proxy HTTP. */
    public static void finalizarHeadersProxyBinario(Exchange exchange) {
        var in = exchange.getIn();
        byte[] bodyBytes = in.getBody(byte[].class);
        if (bodyBytes != null) {
            in.setHeader(Exchange.CONTENT_LENGTH, bodyBytes.length);
        }

        String contentType = in.getHeader(Exchange.CONTENT_TYPE, String.class);
        if (contentType == null || contentType.isBlank()) {
            contentType = in.getHeader("Content-Type", String.class);
        }
        if (contentType != null && !contentType.isBlank()) {
            in.setHeader(Exchange.CONTENT_TYPE, contentType);
        }

        String method = in.getHeader(Exchange.HTTP_METHOD, String.class);
        if (method == null || method.isBlank()) {
            method = in.getHeader("CamelHttpMethod", String.class);
        }
        if (method != null && !method.isBlank()) {
            in.setHeader(Exchange.HTTP_METHOD, method);
        }

        copiarHeaderSePresente(in, "X-Correlation-ID");
        copiarHeaderSePresente(in, "X-Id-Usuario");
        in.setHeader(Exchange.HTTP_QUERY, in.getHeader(Exchange.HTTP_QUERY, String.class));
    }

    private static void copiarHeaderSePresente(org.apache.camel.Message in, String header) {
        String value = in.getHeader(header, String.class);
        if (value != null && !value.isBlank()) {
            in.setHeader(header, value);
        }
    }

}
