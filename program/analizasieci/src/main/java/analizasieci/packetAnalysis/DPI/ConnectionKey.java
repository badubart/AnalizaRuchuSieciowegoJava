package analizasieci.packetAnalysis.DPI.protocolMatchers;

/**
 * Znormalizowany, dwukierunkowy klucz połączenia sieciowego.
 * <p>
 * Aby pakiety obu kierunków strumienia trafiały do tego samego wpisu, para
 * (adres, port) o "niższej" wartości zapisywana jest zawsze jako <em>low</em>,
 * a wyższa jako <em>high</em>. Dzięki temu {@code of(A,B)} i {@code of(B,A)}
 * dają identyczny klucz. Rekord zapewnia poprawne {@code equals}/{@code hashCode}.
 *
 * @param ipLow   niższy (po normalizacji) adres IP
 * @param portLow port odpowiadający niższemu adresowi
 * @param ipHigh  wyższy adres IP
 * @param portHigh port odpowiadający wyższemu adresowi
 * @param isTcp   {@code true} dla TCP, {@code false} dla UDP
 */
public record ConnectionKey(String ipLow, int portLow, String ipHigh, int portHigh, boolean isTcp) {
    /**
     * Tworzy znormalizowany klucz niezależny od kierunku pakietu.
     *
     * @return klucz, w którym niższa para (ip, port) jest zawsze po stronie low
     */
    public static ConnectionKey of(String srcIp, int srcPort, String dstIp, int dstPort, boolean tcp) {
        if (isLower(srcIp, srcPort, dstIp, dstPort))
            return new ConnectionKey(srcIp, srcPort, dstIp, dstPort, tcp);
        return new ConnectionKey(dstIp, dstPort, srcIp, srcPort, tcp);
    }
    private static boolean isLower(String ip1, int p1, String ip2, int p2) {
        int c = ip1.compareTo(ip2);
        return c < 0 || (c == 0 && p1 <= p2);
    }
}
