package analizasieci.packetAnomalies.anomalies;

import analizasieci.packetAnomalies.AnomalyDetector;
import analizasieci.packetAnomalies.SlidingWindow;
import analizasieci.packetCapture.MyPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.util.HashMap;
import java.util.Map;

public class DosAnomaly implements AnomalyDetector {
    private final long windowMs; private final int threshold;
    private final Map<String, SlidingWindow> byTarget = new HashMap<>();
    public DosAnomaly(long windowMs, int threshold) { this.windowMs = windowMs; this.threshold = threshold; }

    @Override public String inspect(MyPacket pkt, Packet raw, long now) {
        TcpPacket tcp = raw.get(TcpPacket.class);
        if (tcp == null || !tcp.getHeader().getSyn() || tcp.getHeader().getAck()) return null;
        String target = pkt.getDestinationIp() + ":" + pkt.getDestinationPort();
        int rate = byTarget.computeIfAbsent(target, k -> new SlidingWindow(windowMs)).add(now);
        if (rate >= threshold)
            return "Możliwy SYN flood (DoS) na " + target + ": " + rate + " SYN / " + windowMs / 1000 + "s";
        return null;
    }
    @Override public void evictIdle(long now) {
        byTarget.values().removeIf(w -> { w.prune(now); return w.isEmpty(); });
    }
    @Override public String getName() { return "DoS"; }
}