package analizasieci.packetCapture.packetLayers;
import java.nio.ByteBuffer;
import java.util.LinkedHashMap;
import java.util.Map;

public class L5RPC implements ProtocolLayer {
    private final Map<String, String> fields = new LinkedHashMap<>();
    private boolean isNfsPacket = false;

    public L5RPC(byte[] payload, boolean overTcp) {
        if (payload.length < 24) {
            fields.put("Error", "Payload too small for RPC");
            return;
        }

        // Używamy ByteBuffer do wyciągania całych 4-bajtowych "bloków" z pakietu
        ByteBuffer buffer = ByteBuffer.wrap(payload);

        // Jeśli RPC idzie po TCP, pierwsze 4 bajty to "Fragment Header" oznaczający długość, omijamy je.
        if (overTcp) {
            int fragmentHeader = buffer.getInt();
            // Można z niego odczytać długość (ostatnie 31 bitów)
        }

        // CZYTANIE NAGŁÓWKA SUN RPC:
        // 1. XID (Transaction ID) - Identyfikator zapytania/odpowiedzi
        int xid = buffer.getInt();
        fields.put("Transaction ID (XID)", String.format("0x%08x", xid));

        // 2. Message Type (0 = CALL, 1 = REPLY)
        int msgType = buffer.getInt();
        fields.put("Message Type", msgType == 0 ? "Call (0)" : "Reply (1)");

        if (msgType == 0) {
            int rpcVersion = buffer.getInt();
            int programNumber = buffer.getInt();
            int programVersion = buffer.getInt();
            int procedure = buffer.getInt();

            fields.put("RPC Version", String.valueOf(rpcVersion));

            if (programNumber == 100003) {
                isNfsPacket = true;
                fields.put("Program", "NFS (100003)");
                fields.put("NFS Version", String.valueOf(programVersion));
                fields.put("Procedure", String.valueOf(procedure));
            } else if (programNumber == 100000) {
                fields.put("Program", "Portmap (100000)");
            } else {
                fields.put("Program", "Unknown (" + programNumber + ")");
            }
        }
    }

    public boolean isNfs() {
        return isNfsPacket;
    }

    @Override
    public String getProtocolName() {
        return isNfsPacket ? "Network File System (NFS)" : "Remote Procedure Call (RPC)";
    }

    @Override
    public Map<String, String> getFields() {
        return fields;
    }
}