package analizasieci.packetAnomalies.anomalies;

import analizasieci.packetAnomalies.AnomalyDetector;
import analizasieci.packetAnomalies.DistinctWindow;
import analizasieci.packetCapture.MyPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import java.util.HashMap;
import java.util.Map;

public class PortScanAnomaly implements AnomalyDetector {
    private final long windowMs; private final int threshold;
    private final Map<String, DistinctWindow<String>> bySource = new HashMap<>();
    public PortScanAnomaly(long windowMs, int threshold) { this.windowMs = windowMs; this.threshold = threshold; }

    @Override public String inspect(MyPacket pkt, Packet raw, long now) {
        TcpPacket tcp = raw.get(TcpPacket.class);
        if (tcp == null) return null;
        if (!(tcp.getHeader().getSyn() && !tcp.getHeader().getAck())) return null;  // tylko SYN-probe

        String src = pkt.getSourceIp();
        String target = pkt.getDestinationIp() + ":" + pkt.getDestinationPort();
        int distinct = bySource.computeIfAbsent(src, k -> new DistinctWindow<>(windowMs)).add(target, now);
        if (distinct >= threshold)
            return "Skan portów ze źródła " + src + " (" + distinct + " celów / " + windowMs / 1000 + "s)";
        return null;
    }
    @Override public void evictIdle(long now) {
        bySource.values().removeIf(w -> { w.prune(now); return w.isEmpty(); });
    }
    @Override public String getName() { return "PortScan"; }
}