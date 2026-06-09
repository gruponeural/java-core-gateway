package br.com.gruponeural.core.gateway.route;

public class RouteHelper {

    public static String mascararDadosSensiveis(String json) {
        if (json == null || json.isEmpty()) {
            return json;
        }

        try {
            String regex = "(?i)\"(senha|password|token|secret|tokenAcesso)\"\\s*:\\s*\"[^\"]+\"";

            return json.replaceAll(regex, "\"$1\":\"********\"");
        } catch (Exception e) {
            return "[ERRO AO MASCARAR DADOS SENSÍVEIS]";
        }
    }

}
