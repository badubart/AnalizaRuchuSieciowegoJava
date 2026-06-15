package analizasieci.packetCapture.packetLayers;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Warstwa protokołu HTTP. Parsuje tekst HTTP na linię startową oraz nagłówki
 * (do pierwszej pustej linii) i udostępnia je jako pola do wyświetlenia.
 */
public class L7HTTP implements ProtocolLayer {
    private final String httpText;

    public L7HTTP(String httpText) {
        this.httpText = httpText;
    }

    @Override
    public String getProtocolName() { return "HTTP"; }

    @Override
    public Map<String, String> getFields() {
        Map<String, String> fields = new LinkedHashMap<>();
        String[] lines = httpText.split("\r\n");
        if (lines.length > 0) {
            fields.put("Line", lines[0]);
            for (int i = 1; i < Math.min(lines.length, 10); i++) {
                if (lines[i].isEmpty()) break;
                String[] parts = lines[i].split(":", 2);
                if (parts.length == 2) fields.put(parts[0].trim(), parts[1].trim());
            }
        }
        return fields;
    }
}