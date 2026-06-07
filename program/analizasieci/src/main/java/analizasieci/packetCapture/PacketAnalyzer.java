package analizasieci.packetCapture;

import analizasieci.packetAnomalies.AnomalyEngine;
import analizasieci.packetAnomalies.anomalies.*;
import analizasieci.packetCapture.packetLayers.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.ArpOperation;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class PacketAnalyzer {
    private final AnomalyEngine ANOMALY_ENGINE = new AnomalyEngine(List.of(
                new PortScanAnomaly(5000, 20),
                new DosAnomaly(1000, 100),           // 100 SYN/s na cel
                new DdosAnomaly(2000, 50, 500),      // 50 źródeł i 500 pkt / 2s na cel
                new ChecksumContext(),
                new TcpFlagsAnomaly(),
                new LandAttackAnomaly(),
                new Retransmission()
    ));
    public static MyPacket analyze(Packet packet){
        return analyze(packet, System.currentTimeMillis());
    }
    public static MyPacket analyze(Packet packet, long tsMs) {
        MyPacket myPacket = new MyPacket();


        LocalTime timeStamp = LocalTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("HH:mm:ss");
        myPacket.setTimeStamp(timeStamp.format(formatter));
        myPacket.setPacketLength(packet.getRawData().length);
        myPacket.setRawData(packet.getRawData());

        Packet currentPacket = packet;

        while (currentPacket != null) {
            if (currentPacket instanceof EthernetPacket) {
                myPacket.setHighestProtocolName("Ethernet");
                myPacket.addLayer(new L2Ethernet((EthernetPacket) currentPacket));
                myPacket.setInfo("Type: "+currentPacket.get(EthernetPacket.class).getHeader().getType().name());
            }

            else if (currentPacket instanceof Dot1qVlanTagPacket) {
                myPacket.setHighestProtocolName("VLAN");
                myPacket.addLayer(new L2VLAN((Dot1qVlanTagPacket) currentPacket));
                myPacket.setInfo("VLAN ID: "+currentPacket.get(Dot1qVlanTagPacket.class).getHeader().getVidAsInt());
            }
            else if (currentPacket instanceof ArpPacket) {
                myPacket.setHighestProtocolName("ARP");
                myPacket.addLayer(new L2ARP((ArpPacket) currentPacket));
                ArpPacket arp = packet.get(ArpPacket.class);
                if(arp.getHeader().getOperation()== ArpOperation.REQUEST)
                    myPacket.setInfo("Who has "+arp.getHeader().getDstProtocolAddr().getHostAddress()+"?");
                else {
                    myPacket.setInfo(arp.getHeader().getSrcProtocolAddr().getHostAddress() + " is at "+arp.getHeader().getSrcProtocolAddr().getHostAddress());
                }
            }

            else if (currentPacket instanceof IpV4Packet) {
                IpV4Packet ipv4 = (IpV4Packet) currentPacket;

                myPacket.setSourceIp(ipv4.getHeader().getSrcAddr().getHostAddress());
                myPacket.setDestinationIp(ipv4.getHeader().getDstAddr().getHostAddress());
                myPacket.setHighestProtocolName("IPv4");
                myPacket.setInfo("TTL: "+ipv4.getHeader().getTtlAsInt()+", protocol "+ipv4.getHeader().getProtocol().name());
                myPacket.addLayer(new L3IPv4(ipv4));

            }
            else if (currentPacket instanceof IpV6Packet) {
                IpV6Packet ipv6 = (IpV6Packet) currentPacket;

                myPacket.setSourceIp(ipv6.getHeader().getSrcAddr().getHostAddress());
                myPacket.setDestinationIp(ipv6.getHeader().getDstAddr().getHostAddress());
                myPacket.setHighestProtocolName("IPv6");
                myPacket.setInfo("HopLimit: " + ipv6.getHeader().getHopLimitAsInt() + ", next: " + ipv6.getHeader().getNextHeader().name());
                myPacket.addLayer(new L3IPv6(ipv6));
            }

            else if (currentPacket instanceof IcmpV4CommonPacket) {
                myPacket.setHighestProtocolName("ICMP");
                myPacket.setInfo(currentPacket.get(IcmpV4CommonPacket.class).getHeader().getType().valueAsString());
                myPacket.addLayer(new L3ICMP((IcmpV4CommonPacket) currentPacket));
            }

            else if (currentPacket instanceof TcpPacket) {
                TcpPacket tcp = (TcpPacket) currentPacket;

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
                myPacket.setInfo(flags.toString());

                myPacket.addLayer(new L4TCP(tcp));

                if (tcp.getPayload() != null) {
                    L7PacketAnalyzer.analyze(tcp.getPayload().getRawData(), tcp, myPacket);
                }
            }
            else if (currentPacket instanceof UdpPacket) {
                UdpPacket udp = (UdpPacket) currentPacket;

                myPacket.setSourcePort(udp.getHeader().getSrcPort().valueAsInt());
                myPacket.setDestinationPort(udp.getHeader().getDstPort().valueAsInt());
                myPacket.setHighestProtocolName("UDP");
                myPacket.setInfo(udp.getHeader().getSrcPort().valueAsInt() + " → " + udp.getHeader().getDstPort().valueAsInt());
                myPacket.addLayer(new L4UDP(udp));


                if (udp.getPayload() instanceof DnsPacket) {
                    myPacket.setHighestProtocolName("DNS");
                    myPacket.addLayer(new L7DNS((DnsPacket) udp.getPayload()));
                }

                else if (udp.getPayload() != null) {
                    L7PacketAnalyzer.analyze(udp.getPayload().getRawData(), udp, myPacket);
                }
            }

            currentPacket = currentPacket.getPayload();
        }

        return myPacket;
    }
}