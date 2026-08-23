package br.com.gruponeural.core.gateway.security;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class SessaoGatewayCache {

  private record CacheEntry(boolean ativa, long expiresAtMs) {
  }

  @ConfigProperty(name = "gateway.sessao-cache.ttl-seconds", defaultValue = "45")
  long ttlSeconds;

  private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();

  public Boolean get(String idSessao, String identityId) {
    CacheEntry entry = cache.get(key(idSessao, identityId));
    if (entry == null) {
      return null;
    }
    if (System.currentTimeMillis() >= entry.expiresAtMs) {
      cache.remove(key(idSessao, identityId));
      return null;
    }
    return entry.ativa();
  }

  public void put(String idSessao, String identityId, boolean ativa) {
    long expiresAt = System.currentTimeMillis() + Duration.ofSeconds(ttlSeconds).toMillis();
    cache.put(key(idSessao, identityId), new CacheEntry(ativa, expiresAt));
  }

  private static String key(String idSessao, String identityId) {
    return idSessao + ":" + identityId;
  }

}
