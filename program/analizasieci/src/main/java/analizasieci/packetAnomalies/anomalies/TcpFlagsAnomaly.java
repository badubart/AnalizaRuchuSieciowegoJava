package analizasieci.packetAnomalies.anomalies;

import analizasieci.packetAnomalies.AnomalyDetector;
import analizasieci.packetCapture.MyPacket;
import org.pcap4j.packet.Packet;

/**
 * Detektor niedozwolonych kombinacji flag TCP używanych w skanowaniu.
 * Rozpoznaje skan NULL (brak flag), skan XMAS (FIN+PSH+URG) oraz nielegalne SYN+FIN.
 */
public class TcpFlagsAnomaly implements AnomalyDetector {
    @Override public String inspect(MyPacket pkt, Packet raw, long now) {
        org.pcap4j.packet.TcpPacket tcp = raw.get(org.pcap4j.packet.TcpPacket.class);
        if (tcp == null) return null;
        var h = tcp.getHeader();
        boolean syn=h.getSyn(), ack=h.getAck(), fin=h.getFin(), rst=h.getRst(), psh=h.getPsh(), urg=h.getUrg();
        if (!syn && !ack && !fin && !rst && !psh && !urg) return "Pakiet NULL (skan NULL)";
        if (fin && psh && urg && !ack)                    return "Pakiet XMAS (skan Xmas)";
        if (syn && fin)                                    return "Niedozwolona kombinacja SYN+FIN";
        return null;
    }
    @Override public String getName() { return "TcpFlags"; }
}