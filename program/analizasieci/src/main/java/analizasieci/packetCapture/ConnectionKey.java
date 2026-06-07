package analizasieci.packetCapture;

public record ConnectionKey(String ipLow, int portLow, String ipHigh, int portHigh, boolean isTcp) {
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
