package analizasieci.packetCapture.packetLayers;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Warstwa SSH. Prezentuje pierwszą linię ruchu SSH (najczęściej baner wersji).
 */
public class L7SSH implements ProtocolLayer{
    private final Map<String, String> fields = new LinkedHashMap<>();
    /**
     * Buduje warstwę z surowego ładunku SSH.
     *
     * @param p bajty ładunku SSH
     */
    public L7SSH(byte[] p) {
        String first = new String(p, 0, Math.min(p.length, 256), StandardCharsets.UTF_8)
                .split("\r\n", 2)[0].trim();
        if (!first.isEmpty()) fields.put("SSH " + " line", first);
    }
    @Override public String getProtocolName() { return "SSH"; }
    @Override public Map<String, String> getFields() { return fields; }
}
