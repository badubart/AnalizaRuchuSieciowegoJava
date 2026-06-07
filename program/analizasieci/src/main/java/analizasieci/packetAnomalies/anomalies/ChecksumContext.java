package analizasieci.packetAnomalies.anomalies;

import analizasieci.packetAnomalies.AnomalyDetector;
import analizasieci.packetCapture.MyPacket;
import org.pcap4j.packet.Packet;

import java.net.InetAddress;

public class ChecksumContext implements AnomalyDetector {
    public InetAddress srcIp;
    public InetAddress dstIp;

    @Override
    public String getName() { return "Checksum"; }
    @Override
    public String inspect(MyPacket packet, Packet raw, long nowMs) { return "Temp"; }
}
