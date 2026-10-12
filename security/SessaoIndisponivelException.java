package br.com.gruponeural.core.gateway.security;

/**
 * Falha de infraestrutura ao validar a sessão (timeout, conexão recusada, 5xx do serviço de sessão).
 * Não é SecurityException: o cliente recebe 503 e não deve ser deslogado.
 */
public class SessaoIndisponivelException extends RuntimeException {

  public SessaoIndisponivelException(String motivoInterno) {
    super(motivoInterno);
  }

  public SessaoIndisponivelException(String motivoInterno, Throwable causa) {
    super(motivoInterno, causa);
  }
}
