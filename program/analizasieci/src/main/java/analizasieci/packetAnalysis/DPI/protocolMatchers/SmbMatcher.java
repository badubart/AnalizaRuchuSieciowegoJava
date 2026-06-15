package analizasieci.packetAnalysis.DPI.protocolMatchers;

import analizasieci.packetCapture.packetLayers.L7SMB;
import analizasieci.packetCapture.packetLayers.ProtocolLayer;

/**
 * Matcher protokołu SMB/CIFS (TCP, porty 445/139).
 * Rozpoznaje sygnaturę "\\xFFSMB" (SMB1) lub "\\xFESMB" (SMB2); dla portu 139
 * uwzględnia 4-bajtowy nagłówek sesji NetBIOS (przesunięcie offsetu).
 */
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
