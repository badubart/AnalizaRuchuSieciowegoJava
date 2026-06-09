package analizasieci.packetCapture.packetLayers;

import org.pcap4j.packet.UdpPacket;

import java.util.LinkedHashMap;
import java.util.Map;

public class L4UDP implements ProtocolLayer{
    private final UdpPacket packet;
    public L4UDP(UdpPacket packet) {
        this.packet = packet;
    }

    @Override
    public String getProtocolName() {
        return "UDP";
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
