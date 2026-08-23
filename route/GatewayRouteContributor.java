package br.com.gruponeural.core.gateway.route;

/**
 * Registra {@link RoutePath} no {@link GatewayRouteRegistry} na inicialização.
 */
public interface GatewayRouteContributor {

    void contribute(GatewayRouteBuilder builder);

}
