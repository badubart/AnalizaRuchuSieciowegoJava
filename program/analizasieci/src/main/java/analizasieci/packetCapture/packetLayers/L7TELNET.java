package analizasieci.packetCapture.packetLayers;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Warstwa Telnet. Rozpoznaje negocjację opcji (IAC + WILL/WONT/DO/DONT) albo
 * oznacza ładunek jako dane.
 */
public class L7TELNET implements ProtocolLayer{
    private final Map<String, String> fields = new LinkedHashMap<>();
    /**
     * Buduje warstwę z surowego ładunku Telnet.
     *
     * @param p bajty ładunku Telnet
     */
    public L7TELNET(byte[] p) {
        if (p.length >= 3 && (p[0] & 0xFF) == 0xFF) {
            fields.put("Type", "Option negotiation");
            fields.put("Command", cmd(p[1] & 0xFF) + " option " + (p[2] & 0xFF));
        } else fields.put("Type", "Data");
    }
    private static String cmd(int c) {
        return switch (c) { case 0xFB->"WILL"; case 0xFC->"WONT"; case 0xFD->"DO"; case 0xFE->"DONT";
            default->"0x"+Integer.toHexString(c); };
    }
    @Override public String getProtocolName() { return "Telnet"; }
    @Override public Map<String, String> getFields() { return fields; }
}
