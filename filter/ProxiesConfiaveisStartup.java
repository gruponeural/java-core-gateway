package br.com.gruponeural.core.gateway.filter;

import org.eclipse.microprofile.config.ConfigProvider;

import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

/** Valida {@code gateway.proxies-confiaveis} na subida: "nenhum" junto com IP/CIDR ou entrada inválida impede o boot. */
@ApplicationScoped
public class ProxiesConfiaveisStartup {

  void onStart(@Observes StartupEvent event) {
    RateLimitFilter.validarProxiesNaSubida(
        ConfigProvider.getConfig().getOptionalValues(RateLimitFilter.PROP_PROXIES, String.class));
  }
}
