package analizasieci.packetAnomalies.anomalies;

import analizasieci.packetAnomalies.AnomalyDetector;
import analizasieci.packetCapture.MyPacket;
import org.pcap4j.packet.*;

import java.net.InetAddress;


public class ChecksumAnomaly implements AnomalyDetector {
    @Override public String inspect(MyPacket pkt, Packet raw, long now) {
        InetAddress srcIp = null, dstIp = null;
        IpV4Packet ip4 = raw.get(IpV4Packet.class);
        if (ip4 != null) {
            srcIp = ip4.getHeader().getSrcAddr();
            dstIp = ip4.getHeader().getDstAddr();
            if (!ip4.getHeader().hasValidChecksum(false))          // IPv4 ma sumę w nagłówku
                return "IPv4 Checksum";
        } else {
            IpV6Packet ip6 = raw.get(IpV6Packet.class);
            if (ip6 != null) {
                srcIp = ip6.getHeader().getSrcAddr();
                dstIp = ip6.getHeader().getDstAddr();
            }
        }

        TcpPacket tcp = raw.get(TcpPacket.class);
        if (tcp != null && srcIp != null && !tcp.hasValidChecksum(srcIp, dstIp, false))
            return "TCP Checksum";

        UdpPacket udp = raw.get(UdpPacket.class);
        if (udp != null && srcIp != null && !udp.hasValidChecksum(srcIp, dstIp, true))
            return "UDP Checksum";

        return null;

    }
    @Override public String getName() { return "Checksum"; }
}

