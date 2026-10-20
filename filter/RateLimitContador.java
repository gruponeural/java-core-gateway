package br.com.gruponeural.core.gateway.filter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicInteger;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;

/**
 * Contador de janela fixa por chave, em memória, com teto de entradas (Caffeine
 * {@code maximumSize}) e expiração ({@code expireAfterWrite} = janela).
 */
public final class RateLimitContador {

  private final Cache<String, Janela> janelas;
  private final long janelaNanos;
  private final Ticker ticker;

  public RateLimitContador(long maximoEntradas, Duration janela) {
    this(maximoEntradas, janela, Ticker.systemTicker());
  }

  RateLimitContador(long maximoEntradas, Duration janela, Ticker ticker) {
    this.janelaNanos = janela.toNanos();
    this.ticker = ticker;
    this.janelas = Caffeine.newBuilder()
        .maximumSize(maximoEntradas)
        .expireAfterWrite(janela)
        .ticker(ticker)
        .executor(Runnable::run)
        .build();
  }

  /** Conta uma tentativa e devolve {@code false} se passou do limite na janela atual. */
  public boolean permitir(String chave, int limite) {
    long agora = ticker.read();
    Janela j = janelas.asMap().compute(chave, (k, atual) -> {
      if (atual == null || agora - atual.inicioNanos >= janelaNanos) {
        return new Janela(agora);
      }
      atual.contagem.incrementAndGet();
      return atual;
    });
    return j.contagem.get() <= limite;
  }

  void limpar() {
    janelas.cleanUp();
  }

  long tamanho() {
    return janelas.estimatedSize();
  }

  /** Hash curto (12 hex do SHA-256) para log, sem gravar o IP. */
  public static String hashParaLog(String chave) {
    try {
      byte[] d = MessageDigest.getInstance("SHA-256").digest(String.valueOf(chave).getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(d, 0, 6);
    } catch (NoSuchAlgorithmException e) {
      return "-";
    }
  }

  private static final class Janela {
    final long inicioNanos;
    final AtomicInteger contagem = new AtomicInteger(1);

    Janela(long inicioNanos) {
      this.inicioNanos = inicioNanos;
    }
  }
}
