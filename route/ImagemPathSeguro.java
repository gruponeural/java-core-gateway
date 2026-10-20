package br.com.gruponeural.core.gateway.route;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

import br.com.gruponeural.core.geral.enumerator.ImagemBancoEnum;

/**
 * Regras de caminho da rota pública {@code imagem/obter}: o sufixo chega codificado (@Encoded), é
 * decodificado uma única vez, cada segmento só aceita {@code [A-Za-z0-9._-]} (sem {@code .} e {@code ..})
 * e a URL final, normalizada, precisa continuar dentro do destino configurado da rota.
 */
public final class ImagemPathSeguro {

  public static final String ORIGEM_OBTER = "obter";
  private static final Pattern SEGMENTO = Pattern.compile("^[A-Za-z0-9._-]+$");
  private static final Pattern DESTINO_IMAGEM_OBTER = Pattern.compile("(^|.*/)imagem/obter/?$");

  /** Recursos de imagem expostos no gateway, com e sem o domínio como prefixo (ex.: no CC). */
  private static final Set<String> RECURSOS_PUBLICOS = recursosPublicos();

  private ImagemPathSeguro() {
  }

  private static Set<String> recursosPublicos() {
    Set<String> recursos = new LinkedHashSet<>();
    for (ImagemBancoEnum banco : ImagemBancoEnum.values()) {
      recursos.add(banco.getRecurso());
      recursos.add(banco.getDominio() + "/" + banco.getRecurso());
    }
    return Set.copyOf(recursos);
  }

  /** A rota registrada é a de obter imagem (destino termina em {@code imagem/obter}). */
  public static boolean ehRotaImagemObter(RegisteredRoute route) {
    return route != null
        && route.path() != null
        && route.path().getDestino() != null
        && DESTINO_IMAGEM_OBTER.matcher(route.path().getDestino()).matches();
  }

  /** Segmento já decodificado aceito: só {@code [A-Za-z0-9._-]}, sem {@code .} e {@code ..}. */
  public static boolean segmentoValido(String segmento) {
    return segmento != null
        && SEGMENTO.matcher(segmento).matches()
        && !".".equals(segmento)
        && !"..".equals(segmento);
  }

  /**
   * Path público exato: {@code /<recurso>/obter} ou {@code /<recurso>/obter/<segmento válido>}, com
   * {@code <recurso>} vindo de {@link ImagemBancoEnum}. Recebe o path já decodificado pelo JAX-RS.
   */
  public static boolean ehPathPublico(String requestPath) {
    if (requestPath == null || !requestPath.startsWith("/")) {
      return false;
    }
    String path = requestPath.substring(1);
    for (String recurso : RECURSOS_PUBLICOS) {
      String rota = recurso + "/" + ORIGEM_OBTER;
      if (path.equals(rota)) {
        return true;
      }
      if (path.startsWith(rota + "/")) {
        String resto = path.substring(rota.length() + 1);
        if (resto.indexOf('/') < 0 && segmentoValido(resto)) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Monta a URL de destino a partir do sufixo após o serviço ainda codificado (ex.: {@code obter/abc}).
   * Vazio quando qualquer regra falha; quem chama responde 400 sem detalhar o motivo.
   */
  public static Optional<URI> destinoSeguro(String baseUrl, RegisteredRoute route, String sufixoCodificado) {
    if (baseUrl == null || route == null || sufixoCodificado == null) {
      return Optional.empty();
    }
    String origem = route.path().getOrigem();
    String destino = route.path().getDestino().replaceAll("^/+", "").replaceAll("/+$", "");
    String sufixo = sufixoCodificado.startsWith("/") ? sufixoCodificado.substring(1) : sufixoCodificado;

    StringBuilder tail = new StringBuilder();
    if (!sufixo.equals(origem)) {
      if (!sufixo.startsWith(origem + "/")) {
        return Optional.empty();
      }
      String resto = sufixo.substring(origem.length() + 1);
      // split com limite -1 mantém segmentos vazios (//, barra final, caminho absoluto) para recusar.
      for (String bruto : resto.split("/", -1)) {
        Optional<String> decodificado = decodificarUmaVez(bruto);
        if (decodificado.isEmpty() || !segmentoValido(decodificado.get())) {
          return Optional.empty();
        }
        tail.append('/').append(decodificado.get());
      }
    }

    try {
      String base = baseUrl.replaceAll("/+$", "");
      URI baseDestino = URI.create(base + "/" + destino).normalize();
      URI alvo = URI.create(base + "/" + destino + tail).normalize();
      String prefixo = baseDestino.toString();
      String final_ = alvo.toString();
      if (!final_.equals(prefixo) && !final_.startsWith(prefixo + "/")) {
        return Optional.empty();
      }
      return Optional.of(alvo);
    } catch (IllegalArgumentException e) {
      return Optional.empty();
    }
  }

  /** Decodifica {@code %XX} uma única vez em UTF-8 estrito; {@code +} não vira espaço (é path, não query). */
  static Optional<String> decodificarUmaVez(String bruto) {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream(bruto.length());
    for (int i = 0; i < bruto.length(); i++) {
      char c = bruto.charAt(i);
      if (c == '%') {
        if (i + 2 >= bruto.length()) {
          return Optional.empty();
        }
        int alto = Character.digit(bruto.charAt(i + 1), 16);
        int baixo = Character.digit(bruto.charAt(i + 2), 16);
        if (alto < 0 || baixo < 0) {
          return Optional.empty();
        }
        bytes.write((alto << 4) | baixo);
        i += 2;
      } else if (c > 0x7F) {
        return Optional.empty();
      } else {
        bytes.write(c);
      }
    }
    try {
      return Optional.of(StandardCharsets.UTF_8.newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(bytes.toByteArray()))
          .toString());
    } catch (CharacterCodingException e) {
      return Optional.empty();
    }
  }

}
