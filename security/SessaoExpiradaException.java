package br.com.gruponeural.core.gateway.security;

/** Falha de sessão/JWT (sem token, inválido, sem upn/sid, sessão inativa). O cliente recebe o texto único de sessão expirada. */
public class SessaoExpiradaException extends SecurityException {

  public SessaoExpiradaException(String motivoInterno) {
    super(motivoInterno);
  }

  public SessaoExpiradaException(String motivoInterno, Throwable causa) {
    super(motivoInterno, causa);
  }
}
