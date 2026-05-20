package analizasieci.packetCapture.packetLayers;

import org.pcap4j.packet.IpV4Packet;

import java.util.LinkedHashMap;
import java.util.Map;

public class L3IPv4 implements ProtocolLayer {
    private final IpV4Packet packet;
    public L3IPv4(IpV4Packet packet){
        this.packet = packet;
    }
    @Override
    public String getProtocolName(){
        return "IPv4";
    }

    @Override
    public Map<String, String> getFields() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("SrcIP", packet.getHeader().getSrcAddr().getHostAddress());
        fields.put("DstIp", packet.getHeader().getDstAddr().getHostAddress());
        fields.put("TTL", String.valueOf(packet.getHeader().getTtlAsInt()));
        fields.put("Protocol", packet.getHeader().getProtocol().name());
        fields.put("TotalLength", String.valueOf(packet.getHeader().getTotalLengthAsInt()));
        return fields;
    }
}

