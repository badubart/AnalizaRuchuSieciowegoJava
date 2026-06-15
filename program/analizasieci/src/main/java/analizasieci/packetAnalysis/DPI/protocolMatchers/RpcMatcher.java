package analizasieci.packetAnalysis.DPI.protocolMatchers;

import analizasieci.packetCapture.packetLayers.L5RPC;
import analizasieci.packetCapture.packetLayers.ProtocolLayer;

/**
 * Matcher protokołu ONC RPC (TCP i UDP, porty 111/2049 – Portmapper i NFS).
 * Rozpoznaje nagłówek RPC: typ komunikatu (0 = CALL, 1 = REPLY) oraz wersję RPC = 2;
 * dla TCP uwzględnia 4-bajtowy marker fragmentu (przesunięcie offsetu).
 */
public class RpcMatcher  extends ProtocolMatcher{
    public RpcMatcher() { super("RPC", L4Protocol.BOTH, 111, 2049); }   // Portmapper + NFS, TCP i UDP
    @Override public boolean identify(byte[] p, int s, int d, boolean overTcp) {
        int off = overTcp ? 4 : 0;
        if (p.length < off + 12) return false;
        long msgType = u32(p, off + 4);
        long rpcVers = u32(p, off + 8);
        return (msgType == 0 || msgType == 1) && rpcVers == 2;
    }
    @Override public ProtocolLayer createLayer(byte[] p, boolean overTcp) {
        return new L5RPC(p, overTcp);
    }
    private static long u32(byte[] p, int o) {
        return ((long)(p[o]&0xFF)<<24)|((p[o+1]&0xFF)<<16)|((p[o+2]&0xFF)<<8)|(p[o+3]&0xFF);
    }
}
