package analizasieci.packetCapture.packetLayers;

import analizasieci.packetAnomalies.anomalies.ChecksumContext;
import analizasieci.packetAnomalies.Checksummable;
import org.pcap4j.packet.TcpPacket;

import java.util.LinkedHashMap;
import java.util.Map;

public class L4TCP implements ProtocolLayer, Checksummable {
    private final TcpPacket packet;

    public L4TCP(TcpPacket packet) {
        this.packet = packet;
    }

    @Override
    public String getProtocolName() {
        return "TCP";
    }
    @Override
    public boolean verifyChecksum(ChecksumContext ctx) {
        if (packet == null){
            return false;
        }
        if (ctx.srcIp == null || ctx.dstIp == null) {
            System.out.println("Błąd: Brak adresów IP w kontekście!");
            return false;
        }
        return packet.hasValidChecksum(ctx.srcIp, ctx.dstIp, false);
    }
    @Override
    public Map<String, String> getFields() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("SrcPort", String.valueOf(packet.getHeader().getSrcPort().valueAsInt()));
        fields.put("DstPort", String.valueOf(packet.getHeader().getDstPort().valueAsInt()));
        fields.put("SEQ", String.valueOf(packet.getHeader().getSequenceNumberAsLong()));
        fields.put("ACK", String.valueOf(packet.getHeader().getAcknowledgmentNumberAsLong()));
        fields.put("WindowSize", String.valueOf(packet.getHeader().getWindowAsInt()));
        fields.put("Checksum",String.valueOf(packet.getHeader().getChecksum() & 0xFFFF));

        return fields;
    }
}
