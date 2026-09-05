package br.com.gruponeural.core.gateway.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Optional;

import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class PublicValidatorService {

  public void validar(String requestPath, String clientSignature, String clientTimestamp, String clientType) {
    if (requestPath != null && requestPath.contains("/imagem/obter")) {
      return;
    }

    if (clientSignature == null || clientTimestamp == null) {
      throw new SecurityException("Assinatura ou Timestamp ausentes.");
    }
    if (clientType == null || clientType.isBlank()) {
      throw new SecurityException("Header X-GN-Client ausente (site|mobile).");
    }

    String client = clientType.trim().toLowerCase();
    String secret = secretForClient(client);

    validarDriftTempo(clientTimestamp);

    String expectedToken = new HmacUtils(HmacAlgorithms.HMAC_SHA_256, secret)
        .hmacHex(clientTimestamp.getBytes(StandardCharsets.UTF_8));

    if (!MessageDigest.isEqual(
        expectedToken.getBytes(StandardCharsets.UTF_8),
        clientSignature.getBytes(StandardCharsets.UTF_8))) {
      throw new SecurityException("Assinatura do aplicativo inválida.");
    }
  }

  private static String secretForClient(String client) {
    Config config = ConfigProvider.getConfig();
    if ("site".equals(client)) {
      return required(config, "public.validator.secret");
    }
    if ("mobile".equals(client)) {
      Optional<String> mobile = config.getOptionalValue("public.validator.secret.mobile", String.class);
      if (mobile.isEmpty() || mobile.get().isBlank()) {
        throw new SecurityException("Secret mobile não configurado (public.validator.secret.mobile).");
      }
      return mobile.get();
    }
    throw new SecurityException("X-GN-Client inválido (use site ou mobile).");
  }

  private static String required(Config config, String key) {
    Optional<String> v = config.getOptionalValue(key, String.class);
    if (v.isEmpty() || v.get().isBlank()) {
      throw new SecurityException("Secret do gateway não configurado (" + key + ").");
    }
    return v.get();
  }

  private void validarDriftTempo(String timestampStr) {
    try {
      DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMddHHmm");
      LocalDateTime enviado = LocalDateTime.parse(timestampStr, formatter);
      LocalDateTime agora = LocalDateTime.now(ZoneOffset.UTC);

      long diff = Math.abs(java.time.Duration.between(agora, enviado).toMinutes());
      if (diff > 5) {
        throw new SecurityException("Requisição expirada (Timestamp fora da janela permitida).");
      }
    } catch (SecurityException e) {
      throw e;
    } catch (Exception e) {
      throw new SecurityException("Formato de timestamp inválido.");
    }
  }

}
