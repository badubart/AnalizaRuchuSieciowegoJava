package analizasieci.packetCapture.packetLayers;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public class L4TLS implements ProtocolLayer {
    private final Map<String, String> fields = new LinkedHashMap<>();

    public L4TLS(byte[] p) {
        int handshakeType = p[5] & 0xFF;
        fields.put("Version", tlsVersion(p[2] & 0xFF));   // wersja z rekordu (legacy)
        fields.put("HandshakeType", handshakeType == 1 ? "ClientHello (1)"
                : handshakeType == 2 ? "ServerHello (2)"
                  : "Other (" + handshakeType + ")");
        if (handshakeType == 1) {
            String sni = extractSni(p);
            if (sni != null) fields.put("SNI", sni);
        }
    }

    private static String tlsVersion(int minor) {
        return switch (minor) {
            case 1 -> "TLS 1.0"; case 2 -> "TLS 1.1";
            case 3 -> "TLS 1.2"; case 4 -> "TLS 1.3";
            default -> "0x03" + String.format("%02x", minor);
        };
    }

    // server_name z ClientHello — uproszczone, z ochroną przed uciętym payloadem
    private static String extractSni(byte[] p) {
        try {
            int pos = 5 + 4;            // record header (5) + handshake header (4)
            pos += 2 + 32;             // client_version (2) + random (32)
            int sidLen = p[pos] & 0xFF; pos += 1 + sidLen;                       // session_id
            int csLen = ((p[pos] & 0xFF) << 8) | (p[pos+1] & 0xFF); pos += 2 + csLen;  // cipher_suites
            int compLen = p[pos] & 0xFF; pos += 1 + compLen;                     // compression
            pos += 2;                  // extensions_length
            while (pos + 4 <= p.length) {
                int type = ((p[pos] & 0xFF) << 8) | (p[pos+1] & 0xFF);
                int len  = ((p[pos+2] & 0xFF) << 8) | (p[pos+3] & 0xFF);
                pos += 4;
                if (type == 0x0000) {  // server_name
                    int nameLen = ((p[pos+3] & 0xFF) << 8) | (p[pos+4] & 0xFF);
                    return new String(p, pos + 5, nameLen, StandardCharsets.US_ASCII);
                }
                pos += len;
            }
        } catch (RuntimeException e) { e.printStackTrace();}
        return null;
    }

    @Override public String getProtocolName() { return "TLS"; }
    @Override public Map<String, String> getFields() { return fields; }
}