package analizasieci.packetAnalysis.DPI.protocolMatchers;

import analizasieci.packetCapture.packetLayers.L4TLS;
import analizasieci.packetCapture.packetLayers.ProtocolLayer;

/**
 * Matcher protokołu TLS (TCP, porty 443/8443).
 * Rozpoznaje rekord TLS Handshake (ContentType 0x16) z komunikatem ClientHello/ServerHello
 * oraz mapuje port na konkretną usługę (np. 443 → HTTPS, 993 → IMAPS).
 */
public class TlsMatcher extends ProtocolMatcher{
    public TlsMatcher() { super("TLS", L4Protocol.TCP, 443, 8443); }
    @Override public boolean identify(byte[] p, int s, int d, boolean tcp) {
        if (p.length < 6) return false;
        int contentType = p[0] & 0xFF;   // 0x16 = handshake
        int verMajor    = p[1] & 0xFF;   // 0x03
        int verMinor    = p[2] & 0xFF;   // 0x01..0x04
        int handshake   = p[5] & 0xFF;   // 1=ClientHello, 2=ServerHello
        return contentType == 0x16 && verMajor == 0x03 && verMinor <= 0x04
                && (handshake == 0x01 || handshake == 0x02);
    }
    @Override public ProtocolLayer createLayer(byte[] p, boolean tcp) {
        return new L4TLS(p);
    }


    @Override
    public String getSessionName(int srcPort, int dstPort) {
        String app = byPort(dstPort);
        if (app == null) app = byPort(srcPort);
        return app != null ? app : "TLS";
    }
    @Override
    public String getApplicationProtocol(int srcPort, int dstPort) {
        String app = byPort(dstPort);
        return app != null ? app : byPort(srcPort);
    }
    @Override
    public ProtocolLayer createContinuationLayer(byte[] p, boolean overTcp) { return new L4TLS(p); }
    private static String byPort(int port) {
        return switch (port) {
            case 443, 8443 -> "HTTPS"; case 465 -> "SMTPS"; case 993 -> "IMAPS";
            case 995 -> "POP3S"; case 990 -> "FTPS"; case 636 -> "LDAPS"; case 853 -> "DoT";
            default -> null;
        };
    }
}
