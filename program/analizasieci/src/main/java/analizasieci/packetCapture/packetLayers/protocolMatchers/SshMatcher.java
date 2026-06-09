package analizasieci.packetCapture.packetLayers.protocolMatchers;

import analizasieci.packetCapture.packetLayers.L7SSH;
import analizasieci.packetCapture.packetLayers.ProtocolLayer;

public class SshMatcher  extends ProtocolMatcher{
    public SshMatcher() { super("SSH", L4Protocol.TCP, 22); }
    @Override public boolean identify(byte[] p, int s, int d, boolean tcp) {
        return startsWith(p, "SSH-");   // baner "SSH-2.0-OpenSSH_..."
    }
    @Override public ProtocolLayer createLayer(byte[] p, boolean tcp) {
        return new L7SSH(p);
    }
}
