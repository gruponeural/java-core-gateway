package br.com.gruponeural.core.gateway.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;
import org.eclipse.microprofile.config.ConfigProvider;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class PublicValidatorProcessor
    implements Processor {

    @Override
    public void process(Exchange exchange) throws Exception {
        String clientSignature = exchange.getIn().getHeader("X-Signature", String.class);
        String clientTimestamp = exchange.getIn().getHeader("X-Timestamp", String.class);

        if (clientSignature == null || clientTimestamp == null) {
            throw new SecurityException("Assinatura ou Timestamp ausentes.");
        }

        validarDriftTempo(clientTimestamp);

        String secret = ConfigProvider.getConfig().getValue("public.validator.secret", String.class);

        String expectedToken = new HmacUtils(HmacAlgorithms.HMAC_SHA_256, secret)
            .hmacHex(clientTimestamp.getBytes(StandardCharsets.UTF_8));

        if (!MessageDigest
            .isEqual(
                expectedToken.getBytes(StandardCharsets.UTF_8),
                clientSignature.getBytes(StandardCharsets.UTF_8))) {
            throw new SecurityException("Assinatura do aplicativo inválida.");
        }
    }

    private void validarDriftTempo(String timestampStr) {
        try {
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMddHHmm");
            LocalDateTime enviado = LocalDateTime.parse(timestampStr, formatter);
            LocalDateTime agora = LocalDateTime.now();

            long diff = Math.abs(java.time.Duration.between(agora, enviado).toMinutes());
            if (diff > 5) {
                throw new SecurityException("Requisição expirada (Timestamp fora da janela permitida).");
            }
        } catch (Exception e) {
            throw new SecurityException("Formato de timestamp inválido.");
        }
    }

}
