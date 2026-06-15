package analizasieci.packetCapture.packetLayers;
import java.nio.ByteBuffer;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Warstwa ONC RPC (i rozpoznanie NFS). Parsuje nagłówek RPC: XID, typ komunikatu,
 * a dla wywołań (CALL) także numer i wersję programu oraz procedurę; rozpoznaje
 * programy NFS (100003) i Portmap (100000). Dla TCP pomija 4-bajtowy marker fragmentu.
 */
public class L5RPC implements ProtocolLayer {
    private final Map<String, String> fields = new LinkedHashMap<>();
    private boolean isNfsPacket = false;

    /**
     * Buduje warstwę z surowego ładunku RPC.
     *
     * @param payload bajty ładunku RPC
     * @param overTcp {@code true}, gdy RPC jest przenoszone przez TCP (z markerem fragmentu)
     */
    public L5RPC(byte[] payload, boolean overTcp) {
        if (payload.length < 24) {
            fields.put("Error", "Payload too small for RPC");
            return;
        }

        ByteBuffer buffer = ByteBuffer.wrap(payload);

        if (overTcp) {
            int fragmentHeader = buffer.getInt();
        }

        // XID (Transaction ID) - Identyfikator zapytania/odpowiedzi
        int xid = buffer.getInt();
        fields.put("Transaction ID (XID)", String.format("0x%08x", xid));

        // Message Type (0 = CALL, 1 = REPLY)
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

    /** @return {@code true}, gdy rozpoznano ruch NFS (program 100003). */
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