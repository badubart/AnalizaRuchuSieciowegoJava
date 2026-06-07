package analizasieci.packetCapture.packetLayers.protocolMatchers;

import analizasieci.packetCapture.packetLayers.ProtocolLayer;

import java.nio.charset.StandardCharsets;
import java.util.Set;

public abstract class ProtocolMatcher {
    public enum L4Protocol { TCP, UDP, BOTH}
    private final String name;
    private final L4Protocol transportProtocol;
    private final Set<Integer> defaultPorts;

    protected ProtocolMatcher(String name, L4Protocol transportProtocol, Integer... defaultPorts) {
        this.name = name;
        this.transportProtocol = transportProtocol;
        this.defaultPorts = Set.of(defaultPorts);
    }
    public String getName() {
        return name;
    }
    public boolean isDefaultPort(int srcPort, int dstPort) {
        return  defaultPorts.contains(srcPort) || defaultPorts.contains(dstPort);
    }
    public boolean isTcp(boolean overTcp){
        return transportProtocol == L4Protocol.BOTH || (transportProtocol == L4Protocol.TCP) == overTcp;
    }
    public L4Protocol getTransportProtocol() {
        return transportProtocol;
    }

    public abstract boolean identify(byte[] payload, int srcPort, int dstPort, boolean overTcp);

    public abstract ProtocolLayer createLayer(byte[] payload, boolean overTcp);

    protected static boolean startsWith(byte[] p, String ascii) {
        byte[] s = ascii.getBytes(StandardCharsets.US_ASCII);
        if (p.length < s.length) return false;
        for (int i = 0; i < s.length; i++) if (p[i] != s[i]) return false;
        return true;
    }
    protected static boolean startsWithAny(byte[] p, String... prefixes) { // sprawdza czy payload zaczyna sie od któregoś z prefixów (użyteczne dla np. HTTP, SMTP i innych tekstowych)
        for (String s : prefixes) if (startsWith(p, s)) return true;
        return false;
    }
    protected static boolean eq(byte[] p, int off, int... bytes) { // sprawdza czy bity od jakiegos momentu sa rowne danym w argumentach
        if (p.length < off + bytes.length) return false;
        for (int i = 0; i < bytes.length; i++)
            if ((p[off + i] & 0xFF) != (bytes[i] & 0xFF)) return false;
        return true;
    }
    protected static boolean isDigit(byte b) { return b >= '0' && b <= '9'; }
}
