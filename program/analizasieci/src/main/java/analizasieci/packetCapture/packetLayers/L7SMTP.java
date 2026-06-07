package analizasieci.packetCapture.packetLayers;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public class L7SMTP implements ProtocolLayer{
    private final Map<String, String> fields = new LinkedHashMap<>();
    public L7SMTP(byte[] p) {
        String first = new String(p, 0, Math.min(p.length, 256), StandardCharsets.UTF_8)
                .split("\r\n", 2)[0].trim();
        if (!first.isEmpty()) fields.put("SMTP " + " line", first);
    }
    @Override public String getProtocolName() { return "SMTP"; }
    @Override public Map<String, String> getFields() { return fields; }
}
