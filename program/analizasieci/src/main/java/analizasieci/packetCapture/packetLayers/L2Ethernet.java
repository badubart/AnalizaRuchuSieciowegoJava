package analizasieci.packetCapture.packetLayers;

import org.pcap4j.packet.EthernetPacket;
import java.util.LinkedHashMap;
import java.util.Map;

public class L2Ethernet implements ProtocolLayer{
    private final EthernetPacket packet;
    public L2Ethernet(EthernetPacket packet){
        this.packet = packet;
    }
    @Override
    public String getProtocolName(){
        return "Ethernet";
    }
    @Override
    public Map<String, String> getFields(){
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("SrcMAC", packet.getHeader().getSrcAddr().toString());
        fields.put("DstMAC", packet.getHeader().getDstAddr().toString());
        fields.put("Type", packet.getHeader().getType().name() + " (0x"+String.format("%04x", packet.getHeader().getType().value()) + ")");
        return fields;
    }
}