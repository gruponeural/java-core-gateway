package br.com.gruponeural.core.gateway.filter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.logging.Logger;

import io.vertx.core.http.HttpServerRequest;
import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

/**
 * Rate limit em memória por IP e por rota, só nas rotas de autenticação, escrita sensível e
 * leitura pública de ranking ({@link #REGRAS}). Nenhuma outra rota passa pelo contador.
 * <p>
 * Chave: renovar por IP e também por {@code idSessao} do corpo (UUID); entrar-provedor só por IP; entrar, recuperação de senha
 * e confirmação de e-mail por IP e também por conta (CPF/e-mail do corpo, em hash); cadastro, verificar-email,
 * cancelar-cadastro-pendente e ranking/listar só por IP.
 * <p>
 * Properties: {@code gateway.rate-limit.<regra>.limite} (tentativas por janela e por rota),
 * {@code gateway.rate-limit.<regra>.limite-conta} (entrar e recuperação),
 * {@code gateway.rate-limit.janela-segundos} (default 60, também é o {@code expireAfterWrite}),
 * {@code gateway.rate-limit.max-entradas} (default 10000, {@code maximumSize}) e
 * {@code gateway.proxies-confiaveis} (IPs/CIDRs ou {@code nenhum}; default: nenhum proxy confiável,
 * sempre o IP remoto), {@code gateway.proxies-confiaveis.cabecalho} (default X-Forwarded-For) e
 * {@code gateway.rate-limit.sessao-renovar.limite-ip} (default 30). O IP vem de {@link #resolveClientKey}.
 */
@Provider
@Priority(Priorities.AUTHENTICATION - 10)
public class RateLimitFilter implements ContainerRequestFilter {

  private static final Logger LOG = Logger.getLogger(RateLimitFilter.class);

  enum TipoChave { IP, SESSAO, IP_E_CONTA }

  record Regra(String nome, Set<String> paths, int limitePadrao, TipoChave tipo, String campoConta,
      int limiteContaPadrao) {
    String propriedade() {
      return "gateway.rate-limit." + nome + ".limite";
    }

    String propriedadeIp() {
      return "gateway.rate-limit." + nome + ".limite-ip";
    }

    String propriedadeConta() {
      return "gateway.rate-limit." + nome + ".limite-conta";
    }
  }

  static final List<Regra> REGRAS = List.of(
      new Regra("sessao-entrar", Set.of("sessao/entrar"), 20, TipoChave.IP_E_CONTA, "cpf", 5),
      new Regra("sessao-entrar-provedor", Set.of("sessao/entrar-provedor"), 20, TipoChave.IP, null, 0),
      new Regra("sessao-renovar", Set.of("sessao/renovar"), 30, TipoChave.SESSAO, null, 0),
      new Regra("cadastro", Set.of("pessoa/cadastrar", "pessoa/cadastrar-provedor"), 10, TipoChave.IP, null, 0),
      new Regra("verificar-email", Set.of("pessoa/verificar-email"), 5, TipoChave.IP, null, 0),
      new Regra("confirmacao-email", Set.of("pessoa/reenviar-token", "pessoa/confirmar-email"), 3,
          TipoChave.IP_E_CONTA, "email", 3),
      new Regra("cancelar-cadastro-pendente", Set.of("pessoa/cancelar-cadastro-pendente"), 5, TipoChave.IP, null, 0),
      new Regra("recuperacao-senha",
          Set.of("pessoa/recuperar-senha", "pessoa/reenviar-token-senha", "pessoa/redefinir-senha"), 5,
          TipoChave.IP_E_CONTA, "email", 3),
      // Leitura pública da home/paginação; 120/min por IP cobre vários usuários atrás do mesmo NAT.
      new Regra("ranking-listar", Set.of("produto/ranking/listar"), 120, TipoChave.IP, null, 0));

  /** Limite por IP do renovar, além do limite por idSessao. */
  static final int LIMITE_IP_RENOVAR_PADRAO = 30;
  static final String PROP_PROXIES = "gateway.proxies-confiaveis";
  static final String PROP_CABECALHO = "gateway.proxies-confiaveis.cabecalho";
  static final String CABECALHO_PADRAO = "X-Forwarded-For";
  /** Valor explícito que desliga a confiança em proxies (sem diferença de maiúsculas, ignora espaços). */
  static final String PROXIES_NENHUM = "nenhum";

  /**
   * Sem configuração ou com {@code nenhum}: lista vazia (o cabeçalho é ignorado e vale o IP remoto).
   * Não há padrão de faixas privadas. {@code nenhum} junto com IP/CIDR é erro de configuração.
   */
  static ProxiesConfiaveis proxiesConfiaveis(Optional<List<String>> configurado) {
    List<String> valores = configurado.orElse(List.of());
    boolean temNenhum = valores.stream().anyMatch(v -> v != null && PROXIES_NENHUM.equalsIgnoreCase(v.trim()));
    if (temNenhum) {
      boolean temOutro = valores.stream()
          .anyMatch(v -> v != null && !v.trim().isEmpty() && !PROXIES_NENHUM.equalsIgnoreCase(v.trim()));
      if (temOutro) {
        throw new IllegalArgumentException(PROP_PROXIES + ": \"nenhum\" não pode vir junto com IP/CIDR");
      }
      return ProxiesConfiaveis.of(List.of());
    }
    return ProxiesConfiaveis.of(valores);
  }

  /** Validação na subida (ver {@link ProxiesConfiaveisStartup}): configuração inválida impede o boot. */
  static void validarProxiesNaSubida(Optional<List<String>> configurado) {
    proxiesConfiaveis(configurado);
  }

  static String nomeCabecalho(Optional<String> configurado) {
    return configurado.map(String::trim).filter(v -> !v.isEmpty()).orElse(CABECALHO_PADRAO);
  }

  private static final ObjectMapper JSON = new ObjectMapper();
  private static final int MAX_CORPO_LIDO = 16 * 1024;

  @Context
  HttpServerRequest httpServerRequest;

  private volatile Estado estado;

  private record Estado(RateLimitContador contador, ProxiesConfiaveis proxies, Map<String, Integer> limites, Map<String, Integer> limitesConta,
      long janelaSegundos, String cabecalho, int limiteIpRenovar) {
  }

  @Override
  public void filter(ContainerRequestContext requestContext) throws IOException {
    String path = normalizar(requestContext.getUriInfo().getPath());
    Optional<Regra> regra = regraPara(requestContext.getMethod(), path);
    if (regra.isEmpty()) {
      return;
    }
    Estado e = estado();
    String remoto = httpServerRequest != null && httpServerRequest.remoteAddress() != null
        ? httpServerRequest.remoteAddress().hostAddress()
        : null;
    String clientKey = resolveClientKey(requestContext.getHeaderString(e.cabecalho()), remoto, e.proxies());
    Regra r = regra.get();
    byte[] corpo = r.tipo() == TipoChave.IP ? null : lerCorpo(requestContext);

    boolean permitido;
    if (r.tipo() == TipoChave.SESSAO) {
      permitido = e.contador().permitir(path + "|ip:" + clientKey, e.limiteIpRenovar());
      Optional<String> sid = idSessao(corpo);
      if (permitido && sid.isPresent()) {
        permitido = e.contador().permitir(path + "|sid:" + sid.get(), e.limites().get(r.nome()));
      }
    } else {
      permitido = e.contador().permitir(path + "|ip:" + clientKey, e.limites().get(r.nome()));
      if (permitido && r.tipo() == TipoChave.IP_E_CONTA) {
        Optional<String> conta = chaveConta(r, corpo);
        if (conta.isPresent()) {
          permitido = e.contador().permitir(path + "|" + conta.get(), e.limitesConta().get(r.nome()));
        }
      }
    }
    if (!permitido) {
      // Nunca loga IP, conta ou sessão em claro.
      LOG.warnf("Rate limit %s excedido em %s (cliente %s)", r.nome(), path, RateLimitContador.hashParaLog(clientKey));
      String correlationId = org.slf4j.MDC.get("correlationId");
      requestContext.abortWith(resposta429(correlationId, e.janelaSegundos()));
    }
  }

  private static byte[] lerCorpo(ContainerRequestContext ctx) throws IOException {
    if (!ctx.hasEntity()) {
      return null;
    }
    // Lê no máximo MAX_CORPO_LIDO + 1 bytes. Acima do teto não extrai conta, mas o proxy recebe o corpo inteiro.
    InputStream in = ctx.getEntityStream();
    byte[] corpo = lerPrefixo(in);
    ctx.setEntityStream(reenviar(corpo, in));
    return corpo;
  }

  static byte[] lerPrefixo(InputStream in) throws IOException {
    return in.readNBytes(MAX_CORPO_LIDO + 1);
  }

  static InputStream reenviar(byte[] prefixo, InputStream resto) {
    InputStream inicio = new ByteArrayInputStream(prefixo);
    return prefixo.length <= MAX_CORPO_LIDO ? inicio : new java.io.SequenceInputStream(inicio, resto);
  }

  private static Optional<JsonNode> json(byte[] corpo) {
    if (corpo == null || corpo.length == 0 || corpo.length > MAX_CORPO_LIDO) {
      return Optional.empty();
    }
    try {
      JsonNode n = JSON.readTree(corpo);
      return n != null && n.isObject() ? Optional.of(n) : Optional.empty();
    } catch (IOException ex) {
      return Optional.empty();
    }
  }

  /** {@code idSessao} do corpo do renovar, validado como UUID. */
  static Optional<String> idSessao(byte[] corpo) {
    return json(corpo).map(n -> n.path("idSessao").asText(null)).flatMap(v -> {
      try {
        return Optional.of(UUID.fromString(v.trim()).toString());
      } catch (RuntimeException ex) {
        return Optional.empty();
      }
    });
  }

  /** Chave da conta (CPF só dígitos ou e-mail minúsculo), sempre em hash SHA-256. */
  static Optional<String> chaveConta(Regra regra, byte[] corpo) {
    if (regra.tipo() != TipoChave.IP_E_CONTA || regra.campoConta() == null) {
      return Optional.empty();
    }
    return json(corpo).map(n -> n.path(regra.campoConta()).asText(null)).map(v -> {
      String t = v.trim();
      return "cpf".equals(regra.campoConta()) ? t.replaceAll("\\D", "") : t.toLowerCase(Locale.ROOT);
    }).filter(v -> !v.isEmpty()).map(v -> "conta:" + sha256(regra.campoConta() + ":" + v));
  }

  private static String sha256(String v) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(v.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException ex) {
      throw new IllegalStateException(ex);
    }
  }

  static Optional<Regra> regraPara(String metodo, String path) {
    if (path == null || !"POST".equalsIgnoreCase(metodo)) {
      return Optional.empty();
    }
    String p = normalizar(path);
    return REGRAS.stream().filter(r -> r.paths().contains(p)).findFirst();
  }

  private static String normalizar(String path) {
    if (path == null) {
      return null;
    }
    String p = path;
    while (p.startsWith("/")) {
      p = p.substring(1);
    }
    while (p.endsWith("/")) {
      p = p.substring(0, p.length() - 1);
    }
    return p;
  }

  static Response resposta429(String correlationId) {
    return resposta429(correlationId, 60);
  }

  static Response resposta429(String correlationId, long retryAfterSegundos) {
    // Formato de erro padrão. O correlationId segue no header da resposta pelo CorrelationIdFilter.
    Map<String, Object> mensagem = new LinkedHashMap<>();
    mensagem.put("tipo", "AVISO");
    mensagem.put("titulo", "Muitas tentativas");
    mensagem.put("detalhe", "Você fez muitas tentativas. Aguarde alguns minutos e tente novamente.");
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("tipo", "MENSAGEM");
    body.put("mensagem", mensagem);
    body.put("listaViolacao", List.of());
    return Response.status(429)
        .type(MediaType.APPLICATION_JSON_TYPE)
        .header("Retry-After", String.valueOf(retryAfterSegundos))
        .entity(body)
        .build();
  }

  private Estado estado() {
    Estado e = estado;
    if (e == null) {
      synchronized (this) {
        e = estado;
        if (e == null) {
          Config config = ConfigProvider.getConfig();
          long janela = config.getOptionalValue("gateway.rate-limit.janela-segundos", Long.class).orElse(60L);
          long max = config.getOptionalValue("gateway.rate-limit.max-entradas", Long.class).orElse(10_000L);
          Map<String, Integer> limites = new LinkedHashMap<>();
          for (Regra r : REGRAS) {
            limites.put(r.nome(), config.getOptionalValue(r.propriedade(), Integer.class).orElse(r.limitePadrao()));
          }
          ProxiesConfiaveis proxies = proxiesConfiaveis(config.getOptionalValues(PROP_PROXIES, String.class));
          String cabecalho = nomeCabecalho(config.getOptionalValue(PROP_CABECALHO, String.class));
          int limiteIpRenovar = config.getOptionalValue("gateway.rate-limit.sessao-renovar.limite-ip", Integer.class)
              .orElse(LIMITE_IP_RENOVAR_PADRAO);
          Map<String, Integer> limitesConta = new LinkedHashMap<>();
          for (Regra r : REGRAS) {
            if (r.tipo() == TipoChave.IP_E_CONTA) {
              limitesConta.put(r.nome(),
                  config.getOptionalValue(r.propriedadeConta(), Integer.class).orElse(r.limiteContaPadrao()));
            }
          }
          e = new Estado(new RateLimitContador(max, Duration.ofSeconds(janela)), proxies, Map.copyOf(limites),
              Map.copyOf(limitesConta), janela, cabecalho, limiteIpRenovar);
          estado = e;
        }
      }
    }
    return e;
  }

  /**
   * Chave do cliente. Se o IP remoto for um proxy confiável, percorre o cabeçalho configurado da direita
   * para a esquerda e para no primeiro IP que não é proxy confiável. Se o remoto não for confiável
   * (ou a lista estiver vazia), ignora o header e usa o IP remoto. Um valor que não é IP encerra a
   * leitura e vale o último IP válido lido; o valor cru nunca vira chave.
   */
  static String resolveClientKey(String forwarded, String remoto, ProxiesConfiaveis proxies) {
    String atual = ProxiesConfiaveis.normalizarIp(remoto);
    if (atual == null) {
      return "unknown";
    }
    if (forwarded == null || proxies == null || proxies.isVazia() || !proxies.contem(atual)) {
      return atual;
    }
    String[] partes = forwarded.split(",");
    for (int i = partes.length - 1; i >= 0; i--) {
      String parte = partes[i].trim();
      if (parte.isEmpty()) {
        continue;
      }
      String ip = ProxiesConfiaveis.normalizarIp(parte);
      if (ip == null) {
        return atual;
      }
      atual = ip;
      if (!proxies.contem(ip)) {
        return ip;
      }
    }
    return atual;
  }
}
