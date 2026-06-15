package analizasieci.packetAnomalies.anomalies;

import analizasieci.packetAnomalies.AnomalyDetector;
import analizasieci.packetAnomalies.DistinctWindow;
import analizasieci.packetAnomalies.SlidingWindow;
import analizasieci.packetCapture.MyPacket;
import org.pcap4j.packet.Packet;

import java.util.HashMap;
import java.util.Map;

/**
 * Detektor ataku DDoS.
 * Dla każdego celu śledzi jednocześnie liczbę różnych adresów źródłowych
 * ({@link DistinctWindow}) oraz tempo pakietów ({@link SlidingWindow}); anomalię
 * zgłasza, gdy w oknie wystąpi zarówno wiele źródeł, jak i wysokie tempo.
 */
public class DdosAnomaly implements AnomalyDetector {
    private final long windowMs; private final int sourceThreshold; private final int rateThreshold;
    private final Map<String, DistinctWindow<String>> sources = new HashMap<>();
    private final Map<String, SlidingWindow> rate = new HashMap<>();
    /**
     * @param windowMs        długość okna czasowego (ms)
     * @param sourceThreshold próg liczby różnych źródeł
     * @param rateThreshold   próg liczby pakietów w oknie
     */
    public DdosAnomaly(long windowMs, int sourceThreshold, int rateThreshold) {
        this.windowMs = windowMs; this.sourceThreshold = sourceThreshold; this.rateThreshold = rateThreshold;
    }

    @Override public String inspect(MyPacket pkt, Packet raw, long now) {
        String target = pkt.getDestinationIp(), src = pkt.getSourceIp();
        if (target == null || target.isEmpty() || src == null || src.isEmpty()) return null;

        int srcCount = sources.computeIfAbsent(target, k -> new DistinctWindow<>(windowMs)).add(src, now);
        int pps      = rate.computeIfAbsent(target, k -> new SlidingWindow(windowMs)).add(now);
        if (srcCount >= sourceThreshold && pps >= rateThreshold)   // dużo źródeł I wysoki rate
            return "Możliwy DDoS na " + target + ": " + srcCount + " źródeł, " + pps + " pakietów / " + windowMs / 1000 + "s";
        return null;
    }
    @Override public void evictIdle(long now) {
        sources.values().removeIf(w -> { w.prune(now); return w.isEmpty(); });
        rate.values().removeIf(w -> { w.prune(now); return w.isEmpty(); });
    }
    @Override public String getName() { return "DDoS"; }
}