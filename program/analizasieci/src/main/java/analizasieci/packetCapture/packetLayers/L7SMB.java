package analizasieci.packetCapture.packetLayers;

import java.util.LinkedHashMap;
import java.util.Map;

public class L7SMB implements ProtocolLayer{
    private final Map<String, String> fields = new LinkedHashMap<>();
    public L7SMB(byte[] p) {
        int off = ((p[0] & 0xFF) == 0xFF || (p[0] & 0xFF) == 0xFE) ? 0 : 4;
        int marker = p[off] & 0xFF;
        fields.put("Dialect", marker == 0xFF ? "SMB1" : "SMB2/3");
        if (marker == 0xFE && p.length >= off + 14) {   // SMB2: Command @ off+12 (little-endian)
            int command = (p[off + 12] & 0xFF) | ((p[off + 13] & 0xFF) << 8);
            fields.put("Command", String.valueOf(command));
        }
    }
    @Override public String getProtocolName() { return "SMB"; }
    @Override public Map<String, String> getFields() { return fields; }
}
