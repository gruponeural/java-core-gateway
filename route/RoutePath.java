package br.com.gruponeural.core.gateway.route;

import lombok.Getter;

@Getter
public class RoutePath {

    private final String origem;
    private final String destino;
    private final String metodo;
    private final Boolean requerAutenticacao;
    /** Quando true, aceita sufixo após {@code origem} e repassa ao destino (ex.: {@code /editar/{id}}). */
    private final boolean matchOnUriPrefix;

    public RoutePath(String origem, String destino, String metodo, Boolean requerAutenticacao) {
        this(origem, destino, metodo, requerAutenticacao, false);
    }

    public RoutePath(String origem, String destino, String metodo, Boolean requerAutenticacao, boolean matchOnUriPrefix) {
        this.origem = origem;
        this.destino = destino;
        this.metodo = metodo;
        this.requerAutenticacao = requerAutenticacao;
        this.matchOnUriPrefix = matchOnUriPrefix;
    }

}
