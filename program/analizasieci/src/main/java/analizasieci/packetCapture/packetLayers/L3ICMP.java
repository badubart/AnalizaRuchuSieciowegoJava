package analizasieci.packetCapture.packetLayers;

import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4EchoPacket;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Warstwa ICMPv4. Udostępnia typ i kod komunikatu ICMP oraz sumę kontrolną.
 */
public class L3ICMP implements ProtocolLayer {
    private final IcmpV4CommonPacket packet;

    public L3ICMP(IcmpV4CommonPacket packet) {
        this.packet = packet;
    }

    @Override
    public String getProtocolName() {
        return "ICMP";
    }

    @Override
    public Map<String, String> getFields() {
        Map<String, String> fields = new LinkedHashMap<>();

        fields.put("Type", packet.getHeader().getType().valueAsString() + " (" + packet.getHeader().getType().value() + ")");
        fields.put("Code", packet.getHeader().getCode().valueAsString() + " (" + packet.getHeader().getCode().value() + ")");
        fields.put("Checksum", String.format("0x%04x", packet.getHeader().getChecksum()));
        return fields;
    }
}