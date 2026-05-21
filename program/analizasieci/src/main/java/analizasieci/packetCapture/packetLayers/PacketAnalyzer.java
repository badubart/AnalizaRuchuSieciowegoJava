package analizasieci.packetCapture.packetLayers;

import analizasieci.packetCapture.MyPacket;
import org.pcap4j.packet.*;

public class PacketAnalyzer {
    private final L7PacketAnalyzer l7Analyzer = new L7PacketAnalyzer();

    public MyPacket analyze(Packet packet, String captureTime) {
        MyPacket myPacket = new MyPacket();

        myPacket.setTimeStamp(captureTime);
        myPacket.setPacketLength(packet.getRawData().length);
        myPacket.setRawData(packet.getRawData());

        Packet currentPacket = packet;

        while (currentPacket != null) {
            if (currentPacket instanceof EthernetPacket) {
                myPacket.setHighestProtocolName("Ethernet");
                myPacket.addLayer(new L2Ethernet((EthernetPacket) currentPacket));
            }

            else if (currentPacket instanceof Dot1qVlanTagPacket) {
                myPacket.setHighestProtocolName("VLAN");
                myPacket.addLayer(new L2VLAN((Dot1qVlanTagPacket) currentPacket));
            }
            else if (currentPacket instanceof ArpPacket) {
                myPacket.setHighestProtocolName("ARP");
                myPacket.addLayer(new L2ARP((ArpPacket) currentPacket));
            }

            else if (currentPacket instanceof IpV4Packet) {
                IpV4Packet ipv4 = (IpV4Packet) currentPacket;

                myPacket.setSourceIp(ipv4.getHeader().getSrcAddr().getHostAddress());
                myPacket.setDestinationIp(ipv4.getHeader().getDstAddr().getHostAddress());
                myPacket.setHighestProtocolName("IPv4");
                myPacket.addLayer(new L3IPv4(ipv4));

            }
            else if (currentPacket instanceof IpV6Packet) {
                IpV6Packet ipv6 = (IpV6Packet) currentPacket;

                myPacket.setSourceIp(ipv6.getHeader().getSrcAddr().getHostAddress());
                myPacket.setDestinationIp(ipv6.getHeader().getDstAddr().getHostAddress());
                myPacket.setHighestProtocolName("IPv6");
                myPacket.addLayer(new L3IPv6(ipv6));
            }

            else if (currentPacket instanceof IcmpV4CommonPacket) {
                myPacket.setHighestProtocolName("ICMP");
                myPacket.addLayer(new L3ICMP((IcmpV4CommonPacket) currentPacket));
            }

            else if (currentPacket instanceof TcpPacket) {
                TcpPacket tcp = (TcpPacket) currentPacket;

                myPacket.setSourcePort(tcp.getHeader().getSrcPort().valueAsInt());
                myPacket.setDestinationPort(tcp.getHeader().getDstPort().valueAsInt());
                myPacket.setHighestProtocolName("TCP");
                myPacket.addLayer(new L4TCP(tcp));

                if (tcp.getPayload() != null) {
                    l7Analyzer.analyze(tcp.getPayload().getRawData(), tcp, myPacket);
                }
            }
            else if (currentPacket instanceof UdpPacket) {
                UdpPacket udp = (UdpPacket) currentPacket;

                myPacket.setSourcePort(udp.getHeader().getSrcPort().valueAsInt());
                myPacket.setDestinationPort(udp.getHeader().getDstPort().valueAsInt());
                myPacket.setHighestProtocolName("UDP");
                myPacket.addLayer(new L4UDP(udp));

                if (udp.getPayload() instanceof DnsPacket) {
                    myPacket.setHighestProtocolName("DNS");
                    myPacket.addLayer(new L7DNS((DnsPacket) udp.getPayload()));
                }

                else if (udp.getPayload() != null) {
                    l7Analyzer.analyze(udp.getPayload().getRawData(), udp, myPacket);
                }
            }

            currentPacket = currentPacket.getPayload();
        }

        return myPacket;
    }
}