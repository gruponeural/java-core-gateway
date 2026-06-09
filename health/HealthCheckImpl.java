package br.com.gruponeural.core.gateway.health;

import java.time.LocalDateTime;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Liveness;

import jakarta.enterprise.context.ApplicationScoped;

@Liveness
@ApplicationScoped
public class HealthCheckImpl
    implements HealthCheck {

    @ConfigProperty(name = "app.version", defaultValue = "unknown")
    String version;

    @ConfigProperty(name = "gateway.health.name", defaultValue = "Gateway Health Check")
    String healthName;

    @Override
    public HealthCheckResponse call() {
        return HealthCheckResponse
            .named(healthName)
            .up()
            .withData("timestamp", LocalDateTime.now().toString())
            .withData("version", version)
            .build();
    }
}
