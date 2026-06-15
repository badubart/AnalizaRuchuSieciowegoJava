package analizasieci.packetCapture.packetLayers;

import org.pcap4j.packet.ArpPacket;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Warstwa ARP. Udostępnia operację (request/reply) oraz adresy MAC i IP obu stron.
 */
public class L2ARP implements ProtocolLayer{
    private final ArpPacket packet;
    public L2ARP(ArpPacket packet){
        this.packet = packet;
    }
    @Override
    public String getProtocolName() {
        return "ARP";
    }

    @Override
    public Map<String, String> getFields() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("Operation", packet.getHeader().getOperation().name());
        fields.put("SrcMAC", packet.getHeader().getSrcHardwareAddr().toString());
        fields.put("SrcIP", packet.getHeader().getSrcProtocolAddr().getHostAddress());
        fields.put("DstMAC", packet.getHeader().getDstHardwareAddr().toString());
        fields.put("DstIP", packet.getHeader().getDstProtocolAddr().getHostAddress());
        return fields;
    }
}
