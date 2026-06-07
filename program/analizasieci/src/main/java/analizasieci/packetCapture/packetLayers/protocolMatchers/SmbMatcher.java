package analizasieci.packetCapture.packetLayers.protocolMatchers;

import analizasieci.packetCapture.packetLayers.L7SMB;
import analizasieci.packetCapture.packetLayers.ProtocolLayer;

public class SmbMatcher  extends ProtocolMatcher{
    public SmbMatcher() { super("SMB", L4Protocol.TCP, 445, 139); }
    @Override public boolean identify(byte[] p, int s, int d, boolean tcp) {
        int off = (s == 139 || d == 139) ? 4 : 0;
        return eq(p, off, 0xFF, 'S', 'M', 'B') || eq(p, off, 0xFE, 'S', 'M', 'B');
    }
    @Override public ProtocolLayer createLayer(byte[] p, boolean tcp) {
        return new L7SMB(p);
    }
}
