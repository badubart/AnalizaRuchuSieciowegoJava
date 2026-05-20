package analizasieci.packetCapture.packetLayers;

import org.pcap4j.packet.TcpPacket;

import java.util.LinkedHashMap;
import java.util.Map;

public class L4TCP implements ProtocolLayer {
    private final TcpPacket packet;

    public L4TCP(TcpPacket packet) {
        this.packet = packet;
    }

    @Override
    public String getProtocolName() {
        return "TCP";
    }

    @Override
    public Map<String, String> getFields() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("SrcPort", String.valueOf(packet.getHeader().getSrcPort().valueAsInt()));
        fields.put("DstPort", String.valueOf(packet.getHeader().getDstPort().valueAsInt()));
        fields.put("SEQ", String.valueOf(packet.getHeader().getSequenceNumberAsLong()));
        fields.put("ACK", String.valueOf(packet.getHeader().getAcknowledgmentNumberAsLong()));
        fields.put("WindowSize", String.valueOf(packet.getHeader().getWindowAsInt()));

        return fields;
    }
}
