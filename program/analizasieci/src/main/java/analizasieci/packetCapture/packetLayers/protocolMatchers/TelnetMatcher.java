package analizasieci.packetCapture.packetLayers.protocolMatchers;

import analizasieci.packetCapture.packetLayers.L7TELNET;
import analizasieci.packetCapture.packetLayers.ProtocolLayer;

public class TelnetMatcher  extends ProtocolMatcher{
    public TelnetMatcher() { super("Telnet", L4Protocol.TCP, 23); }
    @Override public boolean identify(byte[] p, int s, int d, boolean tcp) {
        // negocjacja opcji: IAC (0xFF) + WILL/WONT/DO/DONT (0xFB..0xFE)
        return p.length >= 3 && (p[0] & 0xFF) == 0xFF
                && (p[1] & 0xFF) >= 0xFB && (p[1] & 0xFF) <= 0xFE;
    }
    @Override public ProtocolLayer createLayer(byte[] p, boolean tcp) {
        return new L7TELNET(p);
    }
}
