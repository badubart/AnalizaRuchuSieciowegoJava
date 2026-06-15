package analizasieci.packetCapture.packetLayers;

import analizasieci.packetAnomalies.anomalies.ChecksumContext;
import analizasieci.packetAnomalies.Checksummable;
import org.pcap4j.packet.IpV4Packet;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Warstwa 3 – IPv4. Udostępnia adresy IP, TTL, protokół wyższej warstwy, długość
 * i sumę kontrolną. Implementuje {@link Checksummable} – potrafi zweryfikować
 * poprawność sumy kontrolnej nagłówka.
 */
public class L3IPv4 implements ProtocolLayer, Checksummable {
    private final IpV4Packet packet;
    public L3IPv4(IpV4Packet packet){
        this.packet = packet;
    }
    @Override
    public String getProtocolName(){
        return "IPv4";
    }

    @Override
    public boolean verifyChecksum(ChecksumContext ctx) {
        ctx.srcIp = packet.getHeader().getSrcAddr();
        ctx.dstIp = packet.getHeader().getDstAddr();
        return packet.getHeader().hasValidChecksum(false);
    }

    @Override
    public Map<String, String> getFields() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("SrcIP", packet.getHeader().getSrcAddr().getHostAddress());
        fields.put("DstIp", packet.getHeader().getDstAddr().getHostAddress());
        fields.put("TTL", String.valueOf(packet.getHeader().getTtlAsInt()));
        fields.put("Protocol", packet.getHeader().getProtocol().name());
        fields.put("TotalLength", String.valueOf(packet.getHeader().getTotalLengthAsInt()));
        fields.put("Checksum", String.valueOf(packet.getHeader().getHeaderChecksum() & 0xFFFF));
        return fields;
    }
}

