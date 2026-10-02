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
    /** Quando true, não converte o body de entrada para String (upload multipart/binário). */
    private final boolean preserveBinaryBody;
    /** Cliente único aceito (ex.: {@code monitoramento}); {@code null} = {@code site} e {@code mobile}. */
    private final String clienteExclusivo;

    public RoutePath(String origem, String destino, String metodo, Boolean requerAutenticacao) {
        this(origem, destino, metodo, requerAutenticacao, false);
    }

    public RoutePath(String origem, String destino, String metodo, Boolean requerAutenticacao, boolean matchOnUriPrefix) {
        this(origem, destino, metodo, requerAutenticacao, matchOnUriPrefix, false);
    }

    public RoutePath(
        String origem,
        String destino,
        String metodo,
        Boolean requerAutenticacao,
        boolean matchOnUriPrefix,
        boolean preserveBinaryBody
    ) {
        this(origem, destino, metodo, requerAutenticacao, matchOnUriPrefix, preserveBinaryBody, null);
    }

    private RoutePath(
        String origem,
        String destino,
        String metodo,
        Boolean requerAutenticacao,
        boolean matchOnUriPrefix,
        boolean preserveBinaryBody,
        String clienteExclusivo
    ) {
        this.origem = origem;
        this.destino = destino;
        this.metodo = metodo;
        this.requerAutenticacao = requerAutenticacao;
        this.matchOnUriPrefix = matchOnUriPrefix;
        this.preserveBinaryBody = preserveBinaryBody;
        this.clienteExclusivo = clienteExclusivo;
    }

    /** Mesma rota aceitando só o cliente informado no {@code X-GN-Client} (ex.: {@code monitoramento}). */
    public RoutePath somenteCliente(String cliente) {
        return new RoutePath(origem, destino, metodo, requerAutenticacao, matchOnUriPrefix, preserveBinaryBody,
            cliente == null ? null : cliente.trim().toLowerCase());
    }

}
