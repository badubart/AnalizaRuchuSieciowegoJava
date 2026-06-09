package analizasieci.packetCapture;

import analizasieci.packetAnomalies.AnomalyEngine;
import analizasieci.packetAnomalies.anomalies.*;
import analizasieci.packetCapture.packetLayers.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.ArpOperation;

import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.List;

public class PacketAnalyzer {
    private static final AnomalyEngine ANOMALY_ENGINE = new AnomalyEngine(List.of(
                new PortScanAnomaly(5000, 20),
                new DosAnomaly(1000, 100),           // 100 SYN/s na cel
                new DdosAnomaly(2000, 50, 500),      // 50 źródeł i 500 pkt / 2s na cel
                new ChecksumAnomaly(),
                new TcpFlagsAnomaly(),
                new LandAttackAnomaly()
    ));
    public static MyPacket analyze(Packet packet){
        return analyze(packet, System.currentTimeMillis());
    }
    public static MyPacket analyze(Packet packet, long tsMs) {
        MyPacket myPacket = new MyPacket();


        LocalTime timeStamp = Instant.ofEpochMilli(tsMs).atZone(ZoneId.systemDefault()).toLocalTime();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("HH:mm:ss");
        myPacket.setTimeStamp(timeStamp.format(formatter));
        myPacket.setPacketLength(packet.getRawData().length);
        myPacket.setRawData(packet.getRawData());

        Packet currentPacket = packet;

        while (currentPacket != null) {
            if (currentPacket instanceof EthernetPacket ethernetPacket) {
                myPacket.setHighestProtocolName("Ethernet");
                myPacket.addLayer(new L2Ethernet(ethernetPacket));
                myPacket.setInfo("Type: " + ethernetPacket.getHeader().getType().name());
            } else if (currentPacket instanceof Dot1qVlanTagPacket vlanPacket) {
                myPacket.setHighestProtocolName("VLAN");
                myPacket.addLayer(new L2VLAN(vlanPacket));
                myPacket.setInfo("VLAN ID: " + vlanPacket.getHeader().getVidAsInt());
            } else if (currentPacket instanceof ArpPacket arpPacket) {
                myPacket.addLayer(new L2ARP(arpPacket));
                if (arpPacket.getHeader().getOperation() == ArpOperation.REQUEST) {
                    myPacket.setInfo("Who has " + arpPacket.getHeader().getDstProtocolAddr().getHostAddress() + "?");
                } else {
                    myPacket.setInfo(arpPacket.getHeader().getSrcProtocolAddr().getHostAddress() + " is at " + arpPacket.getHeader().getSrcProtocolAddr().getHostAddress());
                }
            } else if (currentPacket instanceof IpV4Packet ipv4) {
                myPacket.setSourceIp(ipv4.getHeader().getSrcAddr().getHostAddress());
                myPacket.setDestinationIp(ipv4.getHeader().getDstAddr().getHostAddress());
                myPacket.setHighestProtocolName("IPv4");
                myPacket.setInfo("TTL: " + ipv4.getHeader().getTtlAsInt() + ", protocol " + ipv4.getHeader().getProtocol().name());
                myPacket.addLayer(new L3IPv4(ipv4));

            } else if (currentPacket instanceof IpV6Packet ipv6) {
                myPacket.setSourceIp(ipv6.getHeader().getSrcAddr().getHostAddress());
                myPacket.setDestinationIp(ipv6.getHeader().getDstAddr().getHostAddress());
                myPacket.setHighestProtocolName("IPv6");
                myPacket.setInfo("HopLimit: " + ipv6.getHeader().getHopLimitAsInt() + ", next: " + ipv6.getHeader().getNextHeader().name());
                myPacket.addLayer(new L3IPv6(ipv6));
            } else if (currentPacket instanceof IcmpV4CommonPacket icmpPacket) {
                myPacket.setHighestProtocolName("ICMP");
                myPacket.setInfo(icmpPacket.getHeader().getType().valueAsString());
                myPacket.addLayer(new L3ICMP(icmpPacket));
            } else if (currentPacket instanceof TcpPacket tcp) {
                if (tcp.getHeader().getRst() || tcp.getHeader().getFin()) {
                    L7PacketAnalyzer.onConnectionClosed(
                            myPacket.getSourceIp(), myPacket.getSourcePort(),
                            myPacket.getDestinationIp(), myPacket.getDestinationPort(), true);
                }

                myPacket.setSourcePort(tcp.getHeader().getSrcPort().valueAsInt());
                myPacket.setDestinationPort(tcp.getHeader().getDstPort().valueAsInt());
                myPacket.setHighestProtocolName("TCP");
                StringBuilder flags = new StringBuilder();
                if (tcp.getHeader().getSyn()) flags.append("SYN ");
                if (tcp.getHeader().getUrg()) flags.append("URG ");
                if (tcp.getHeader().getAck()) flags.append("ACK ");
                if (tcp.getHeader().getFin()) flags.append("FIN ");
                if (tcp.getHeader().getRst()) flags.append("RST ");
                if (tcp.getHeader().getPsh()) flags.append("PSH ");
                myPacket.setInfo(flags.toString().trim());

                myPacket.addLayer(new L4TCP(tcp));

                if (tcp.getPayload() != null) {
                    L7PacketAnalyzer.analyze(tcp.getPayload().getRawData(), tcp, myPacket);
                }
            } else if (currentPacket instanceof UdpPacket udp) {

                myPacket.setSourcePort(udp.getHeader().getSrcPort().valueAsInt());
                myPacket.setDestinationPort(udp.getHeader().getDstPort().valueAsInt());
                myPacket.setHighestProtocolName("UDP");
                myPacket.setInfo(udp.getHeader().getSrcPort().valueAsInt() + " -> " + udp.getHeader().getDstPort().valueAsInt());
                myPacket.addLayer(new L4UDP(udp));


                if (udp.getPayload() instanceof DnsPacket dnsPacket) {
                    myPacket.setHighestProtocolName("DNS");
                    myPacket.addLayer(new L7DNS(dnsPacket));
                } else if (udp.getPayload() != null) {
                    L7PacketAnalyzer.analyze(udp.getPayload().getRawData(), udp, myPacket);
                }
            }

            currentPacket = currentPacket.getPayload();
        }
        ANOMALY_ENGINE.evictIdle(tsMs);
        ANOMALY_ENGINE.inspect(myPacket, packet, tsMs);

        return myPacket;
    }
    public static java.util.Map<String, Integer> getAnomalyCount() {
        return Collections.unmodifiableMap(ANOMALY_ENGINE.getAnomalyCount());
    }

}