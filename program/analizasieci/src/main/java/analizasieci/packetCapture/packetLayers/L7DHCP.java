package analizasieci.packetCapture.packetLayers;

import java.util.LinkedHashMap;
import java.util.Map;

public class L7DHCP implements ProtocolLayer {
    private final Map<String, String> fields = new LinkedHashMap<>();

    public L7DHCP(byte[] p) {
        fields.put("Op", p[0] == 1 ? "BOOTREQUEST (1)" : "BOOTREPLY (2)");
        Integer type = findOption(p, 53);   // DHCP Message Type
        if (type != null) fields.put("MessageType", dhcpType(type));
    }

    private static Integer findOption(byte[] p, int wanted) {
        int pos = 240;                       // sekcja options zaczyna się po magic cookie
        while (pos < p.length) {
            int code = p[pos] & 0xFF;
            if (code == 255) break;
            if (code == 0) { pos++; continue; }
            if (pos + 1 >= p.length) break;
            int len = p[pos + 1] & 0xFF;
            if (code == wanted && len >= 1 && pos + 2 < p.length) return p[pos + 2] & 0xFF;
            pos += 2 + len;
        }
        return null;
    }

    private static String dhcpType(int t) {
        return switch (t) {
            case 1 -> "DISCOVER"; case 2 -> "OFFER"; case 3 -> "REQUEST";
            case 4 -> "DECLINE";  case 5 -> "ACK";   case 6 -> "NAK";
            case 7 -> "RELEASE";  case 8 -> "INFORM";
            default -> "Type " + t;
        };
    }

    @Override public String getProtocolName() { return "DHCP"; }
    @Override public Map<String, String> getFields() { return fields; }
}