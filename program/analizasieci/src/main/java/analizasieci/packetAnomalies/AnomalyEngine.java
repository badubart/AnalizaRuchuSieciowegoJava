package analizasieci.packetAnomalies;

import analizasieci.packetCapture.MyPacket;
import org.pcap4j.packet.Packet;

import java.util.HashMap;
import java.util.List;
import java.util.Collections;
import java.util.Map;

public class AnomalyEngine {
    private final List<AnomalyDetector> detectors;
    private final Map<String, Integer> anomalyCount= new HashMap<>();
    public AnomalyEngine(List<AnomalyDetector> detectors) {this.detectors = detectors;}

    public void inspect(MyPacket packet, Packet raw, long nowMs) {
        for (AnomalyDetector d : detectors) {
            String reason = d.inspect(packet, raw, nowMs);
            if (reason != null) {
                packet.setAnomaly(true);
                packet.addAnomalyDescription(reason);
                String anomalyName = d.getName();
                if(!anomalyName.equals("Checksum"))
                {
                    anomalyCount.put(anomalyName, anomalyCount.getOrDefault(anomalyName, 0) + 1);
                }

            }
        }
    }

    public void evictIdle(long nowMs) { detectors.forEach(d -> d.evictIdle(nowMs)); }

    public Map<String, Integer> getAnomalyCount() {
        return Collections.unmodifiableMap(anomalyCount);
    }

}
