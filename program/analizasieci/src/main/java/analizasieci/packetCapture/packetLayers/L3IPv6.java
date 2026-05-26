package analizasieci.packetCapture.packetLayers;

import org.pcap4j.packet.IpV6Packet;

import java.util.LinkedHashMap;
import java.util.Map;

public class L3IPv6 implements ProtocolLayer{
    private final IpV6Packet packet;
    public L3IPv6(IpV6Packet packet){
        this.packet = packet;
    }

    @Override
    public String getProtocolName() {
        return "IPv6";
    }

    @Override
    public Map<String, String> getFields() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("SrcIP", packet.getHeader().getSrcAddr().getHostAddress());
        fields.put("DstIP", packet.getHeader().getDstAddr().getHostAddress());
        fields.put("TrafficClass", String.valueOf(packet.getHeader().getTrafficClass().value()));
        fields.put("HopLimit", String.valueOf(packet.getHeader().getHopLimitAsInt()));
        fields.put("NextHeader", packet.getHeader().getNextHeader().name());
        return fields;
    }
}
