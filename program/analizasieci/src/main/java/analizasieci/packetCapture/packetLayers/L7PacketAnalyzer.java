package analizasieci.packetCapture.packetLayers;

import analizasieci.packetCapture.MyPacket;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import java.nio.charset.StandardCharsets;


public class L7PacketAnalyzer {

    public static void analyze(byte[] payloadBytes, Packet l4Packet, MyPacket myPacket) {
        if (payloadBytes == null || payloadBytes.length == 0) {
            return;
        }

        int srcPort = -1;
        int dstPort = -1;
        boolean isTcp = false;

        if (l4Packet instanceof TcpPacket) {
            srcPort = ((TcpPacket) l4Packet).getHeader().getSrcPort().valueAsInt();
            dstPort = ((TcpPacket) l4Packet).getHeader().getDstPort().valueAsInt();
            isTcp = true;
        } else if (l4Packet instanceof UdpPacket) {
            srcPort = ((UdpPacket) l4Packet).getHeader().getSrcPort().valueAsInt();
            dstPort = ((UdpPacket) l4Packet).getHeader().getDstPort().valueAsInt();
        }
        String rawText = new String(payloadBytes, StandardCharsets.UTF_8);

        if (rawText.startsWith("GET ") || rawText.startsWith("POST ") || rawText.startsWith("HTTP/")) {
            myPacket.setHighestProtocolName("HTTP");
            myPacket.addLayer(new L7HTTP(rawText));
        }

        else if (srcPort == 21 || dstPort == 21 || srcPort == 20 || dstPort == 20) {
            myPacket.setHighestProtocolName("FTP");
            myPacket.addLayer(new L7FTP(rawText));
        }
        // 4. 111 - Portmapper, 2049 - NFS
        else if (srcPort == 111 || dstPort == 111 || srcPort == 2049 || dstPort == 2049) {
            L5RPC rpcLayer = new L5RPC(payloadBytes, isTcp);
            myPacket.addLayer(rpcLayer);

            if (rpcLayer.isNfs()) {
                myPacket.setHighestProtocolName("NFS");
            } else {
                myPacket.setHighestProtocolName("RPC");
            }
        }
        else {
            if (srcPort == 443 || dstPort == 443){
                myPacket.setHighestProtocolName("HTTPS");
            }
            else if (srcPort == 22 || dstPort == 22){
                myPacket.setHighestProtocolName("SSH");
            }
            else if (srcPort == 25 || dstPort == 25){
                myPacket.setHighestProtocolName("SMTP");
            }
            else if (srcPort == 23 || dstPort == 23){
                myPacket.setHighestProtocolName("Telnet");
            }
            else {
                myPacket.setHighestProtocolName("Data");
            }
            myPacket.addLayer(new RawData(payloadBytes));
        }
    }
}