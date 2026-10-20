package br.com.gruponeural.core.gateway.filter;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Lista de proxies confiáveis (IPs ou CIDRs, IPv4 e IPv6) vinda de {@code gateway.proxies-confiaveis}.
 * Nunca faz consulta de DNS: só aceita IP literal.
 */
public final class ProxiesConfiaveis {

  private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");
  private static final Pattern IPV6 = Pattern.compile("^[0-9a-fA-F:.]+$");

  private final List<Faixa> faixas;

  private ProxiesConfiaveis(List<Faixa> faixas) {
    this.faixas = faixas;
  }

  public static ProxiesConfiaveis of(List<String> entradas) {
    List<Faixa> faixas = new ArrayList<>();
    if (entradas != null) {
      for (String bruta : entradas) {
        String entrada = bruta == null ? "" : bruta.trim();
        if (entrada.isEmpty()) {
          continue;
        }
        faixas.add(Faixa.parse(entrada));
      }
    }
    return new ProxiesConfiaveis(List.copyOf(faixas));
  }

  public boolean isVazia() {
    return faixas.isEmpty();
  }

  public boolean contem(String ip) {
    InetAddress addr = parseIp(ip);
    if (addr == null) {
      return false;
    }
    for (Faixa f : faixas) {
      if (f.contem(addr)) {
        return true;
      }
    }
    return false;
  }

  /** IP literal normalizado, ou {@code null} se não for um IP. */
  public static String normalizarIp(String valor) {
    InetAddress addr = parseIp(valor);
    return addr == null ? null : addr.getHostAddress();
  }

  static InetAddress parseIp(String valor) {
    if (valor == null) {
      return null;
    }
    String v = valor.trim();
    if (v.isEmpty() || v.length() > 45) {
      return null;
    }
    boolean literal = IPV4.matcher(v).matches() || (v.indexOf(':') >= 0 && IPV6.matcher(v).matches());
    if (!literal) {
      return null;
    }
    try {
      return InetAddress.getByName(v);
    } catch (UnknownHostException e) {
      return null;
    }
  }

  private record Faixa(byte[] rede, int prefixo) {

    static Faixa parse(String entrada) {
      String ip = entrada;
      Integer prefixo = null;
      int barra = entrada.indexOf('/');
      if (barra >= 0) {
        ip = entrada.substring(0, barra);
        try {
          prefixo = Integer.parseInt(entrada.substring(barra + 1).trim());
        } catch (NumberFormatException e) {
          throw new IllegalArgumentException("gateway.proxies-confiaveis: prefixo inválido em " + entrada);
        }
      }
      InetAddress addr = parseIp(ip);
      if (addr == null) {
        throw new IllegalArgumentException("gateway.proxies-confiaveis: não é IP/CIDR: " + entrada);
      }
      byte[] bytes = addr.getAddress();
      int max = bytes.length * 8;
      int p = prefixo == null ? max : prefixo;
      if (p < 0 || p > max) {
        throw new IllegalArgumentException("gateway.proxies-confiaveis: prefixo fora da faixa em " + entrada);
      }
      return new Faixa(bytes, p);
    }

    boolean contem(InetAddress addr) {
      byte[] alvo = addr.getAddress();
      if (alvo.length != rede.length) {
        return false;
      }
      int bitsCheios = prefixo / 8;
      for (int i = 0; i < bitsCheios; i++) {
        if (alvo[i] != rede[i]) {
          return false;
        }
      }
      int resto = prefixo % 8;
      if (resto == 0) {
        return true;
      }
      int mascara = (0xFF << (8 - resto)) & 0xFF;
      return (alvo[bitsCheios] & mascara) == (rede[bitsCheios] & mascara);
    }
  }
}
