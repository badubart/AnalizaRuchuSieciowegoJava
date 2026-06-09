package analizasieci.packetAnomalies;

import analizasieci.packetCapture.MyPacket;
import org.pcap4j.packet.Packet;

public interface AnomalyDetector {
    String getName();
    String inspect(MyPacket packet, Packet raw, long nowMs);

    default void evictIdle(long nowMs) {}
}
