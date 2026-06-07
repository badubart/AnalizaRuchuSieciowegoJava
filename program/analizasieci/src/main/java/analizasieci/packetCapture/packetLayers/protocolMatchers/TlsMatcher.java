package analizasieci.packetCapture.packetLayers.protocolMatchers;

import analizasieci.packetCapture.packetLayers.L4TLS;
import analizasieci.packetCapture.packetLayers.ProtocolLayer;

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
}
