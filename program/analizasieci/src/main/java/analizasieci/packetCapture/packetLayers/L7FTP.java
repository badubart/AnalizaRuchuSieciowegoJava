package analizasieci.packetCapture.packetLayers;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Warstwa FTP (kanał sterujący). Prezentuje pierwszą linię komendy lub odpowiedzi FTP.
 */
public class L7FTP implements ProtocolLayer {
    private final String ftpText;

    public L7FTP(String ftpText) {
        this.ftpText = ftpText;
    }

    @Override
    public String getProtocolName() { return "FTP"; }

    @Override
    public Map<String, String> getFields() {
        Map<String, String> fields = new LinkedHashMap<>();
        String[] lines = ftpText.split("\r\n");
        if (lines.length > 0 && !lines[0].isEmpty()) {
            fields.put("FTP Command/Response", lines[0].trim());
        }
        return fields;
    }
}