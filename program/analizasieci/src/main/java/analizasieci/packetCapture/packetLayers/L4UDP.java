package analizasieci.packetCapture.packetLayers;

import analizasieci.packetAnomalies.anomalies.ChecksumContext;
import analizasieci.packetAnomalies.Checksummable;
import org.pcap4j.packet.UdpPacket;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Warstwa 4 – UDP. Udostępnia porty, długość i sumę kontrolną. Implementuje
 * {@link Checksummable} – weryfikuje sumę kontrolną z użyciem pseudo-nagłówka IP.
 */
public class L4UDP implements ProtocolLayer, Checksummable {
    private final UdpPacket packet;
    public L4UDP(UdpPacket packet) {
        this.packet = packet;
    }

    @Override
    public String getProtocolName() {
        return "UDP";
    }
    @Override
    public boolean verifyChecksum(ChecksumContext ctx) {
        if (packet == null) return false;

        if (ctx.srcIp == null || ctx.dstIp == null) {
            return false;
        }

        return packet.hasValidChecksum(ctx.srcIp, ctx.dstIp, true);
    }
    @Override
    public Map<String, String> getFields() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("SrcPort", String.valueOf(packet.getHeader().getSrcPort().valueAsInt()));
        fields.put("DstPort", String.valueOf(packet.getHeader().getDstPort().valueAsInt()));
        fields.put("Length", String.valueOf(packet.getHeader().getLengthAsInt()));
        fields.put("Checksum", String.valueOf(packet.getHeader().getChecksum() & 0xFFFF));
        return fields;
    }
}
