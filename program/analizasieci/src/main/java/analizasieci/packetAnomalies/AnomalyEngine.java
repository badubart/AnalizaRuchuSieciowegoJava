package analizasieci.packetAnomalies;

import analizasieci.packetCapture.MyPacket;
import org.pcap4j.packet.Packet;

import java.util.List;

public class AnomalyEngine {
    private final List<AnomalyDetector> detectors;
    public AnomalyEngine(List<AnomalyDetector> detectors) {this.detectors = detectors;}

    public void inspect(MyPacket packet, Packet raw, long nowMs) {
        for (AnomalyDetector d : detectors) {
            String reason = d.inspect(packet, raw, nowMs);
            if (reason != null) {
                packet.setAnomaly(true);
                packet.addAnomalyDescription(reason);
            }
        }
    }

    public void evictIdle(long nowMs) { detectors.forEach(d -> d.evictIdle(nowMs)); }

}
