package analizasieci.packetAnomalies.anomalies;

import analizasieci.packetAnomalies.AnomalyDetector;
import analizasieci.packetCapture.MyPacket;
import org.pcap4j.packet.Packet;

/**
 * Detektor ataku LAND.
 * Wykrywa spreparowane pakiety, w których adres i port źródłowy są identyczne
 * z docelowymi (źródło == cel), co potrafiło zawieszać podatne systemy.
 */
public class LandAttackAnomaly implements AnomalyDetector {
    @Override public String inspect(MyPacket pkt, Packet raw, long now) {
        if (pkt.getSourceIp() != null && !pkt.getSourceIp().isEmpty()
                && pkt.getSourceIp().equals(pkt.getDestinationIp())
                && pkt.getSourcePort() == pkt.getDestinationPort())
            return "Atak LAND (źródło == cel: " + pkt.getSourceIp() + ":" + pkt.getSourcePort() + ")";
        return null;
    }
    @Override public String getName() { return "Land"; }
}