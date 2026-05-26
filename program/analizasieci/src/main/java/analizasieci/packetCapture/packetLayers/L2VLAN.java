package analizasieci.packetCapture.packetLayers;

import org.pcap4j.packet.Dot1qVlanTagPacket;

import java.util.LinkedHashMap;
import java.util.Map;

public class L2VLAN implements ProtocolLayer{
    private final Dot1qVlanTagPacket packet;

    public L2VLAN(Dot1qVlanTagPacket packet) {
        this.packet = packet;
    }

    @Override
    public String getProtocolName() {
        return "VLAN";
    }

    @Override
    public Map<String, String> getFields() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("VlanID", String.valueOf(packet.getHeader().getVidAsInt()));
        fields.put("Priority", String.valueOf(packet.getHeader().getPriority()));
        fields.put("DEI", packet.getHeader().getCfi() ? "True" : "False");
        fields.put("Type", packet.getHeader().getType().name());
        return fields;
    }
}
