package analizasieci.packetCapture.packetLayers.protocolMatchers;

import analizasieci.packetCapture.packetLayers.L7DHCP;
import analizasieci.packetCapture.packetLayers.ProtocolLayer;

import java.util.ArrayList;

public class DhcpMatcher extends ProtocolMatcher {
    public DhcpMatcher() { super("DHCP", L4Protocol.UDP, 67, 68); }   // UDP
    @Override public boolean identify(byte[] p, int s, int d, boolean tcp) {
        // magic cookie 0x63825363 na offsecie 236, op = 1/2
        return p.length >= 240 && eq(p, 236, 0x63, 0x82, 0x53, 0x63)
                && (p[0] == 1 || p[0] == 2);
    }
    @Override public ProtocolLayer createLayer(byte[] p, boolean tcp) {
        return new L7DHCP(p);
    }
}
