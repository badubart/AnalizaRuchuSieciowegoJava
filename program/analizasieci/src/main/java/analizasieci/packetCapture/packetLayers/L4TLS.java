package analizasieci.packetCapture.packetLayers;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public class L4TLS implements ProtocolLayer {
    private final Map<String, String> fields = new LinkedHashMap<>();

    public L4TLS(byte[] p) {
        int contentType = p[0] & 0xFF;
        fields.put("Record Type", recordType(contentType));
        fields.put("Version", tlsVersion(p[2] & 0xFF));   // wersja z rekordu (legacy)
        if(contentType == 0x16 && p.length > 5) {
            int handshakeType = p[5] & 0xFF;
            fields.put("HandshakeType", handshakeType == 1 ? "ClientHello (1)"
                    : handshakeType == 2 ? "ServerHello (2)"
                      : "Other (" + handshakeType + ")");
            if (handshakeType == 1) {
                String sni = extractSni(p);
                if (sni != null) fields.put("SNI", sni);
            }
        }
    }

    private static String tlsVersion(int minor) {
        return switch (minor) {
            case 1 -> "TLS 1.0"; case 2 -> "TLS 1.1";
            case 3 -> "TLS 1.2"; case 4 -> "TLS 1.3";
            default -> "0x03" + String.format("%02x", minor);
        };
    }
    private static String recordType(int t) {
        return switch (t) {
            case 0x14 -> "ChangeCipherSpec"; case 0x15 -> "Alert";
            case 0x16 -> "Handshake";        case 0x17 -> "ApplicationData";
            default -> "0x" + Integer.toHexString(t);
        };
    }
    private static String extractSni(byte[] p) {
        try {
            int pos = 5 + 4 + 2 + 32;
            int sidLen = p[pos] & 0xFF; pos += 1 + sidLen;
            int csLen = ((p[pos] & 0xFF) << 8) | (p[pos+1] & 0xFF); pos += 2 + csLen;
            int compLen = p[pos] & 0xFF; pos += 1 + compLen;
            pos += 2;
            while (pos + 4 <= p.length) {
                int type = ((p[pos] & 0xFF) << 8) | (p[pos+1] & 0xFF);
                int len  = ((p[pos+2] & 0xFF) << 8) | (p[pos+3] & 0xFF);
                pos += 4;
                if (type == 0x0000) {
                    int nameLen = ((p[pos+3] & 0xFF) << 8) | (p[pos+4] & 0xFF);
                    return new String(p, pos + 5, nameLen, java.nio.charset.StandardCharsets.US_ASCII);
                }
                pos += len;
            }
        } catch (RuntimeException e) {e.printStackTrace();}
        return null;
    }

    @Override public String getProtocolName() { return "TLS"; }
    @Override public Map<String, String> getFields() { return fields; }
}