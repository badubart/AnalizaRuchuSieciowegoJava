package analizasieci.packetAnomalies;

import analizasieci.packetCapture.MyPacket;
import org.pcap4j.packet.Packet;

import java.util.HashMap;
import java.util.List;
import java.util.Collections;
import java.util.Map;

/**
 * Silnik anomalii spinający wszystkie {@link AnomalyDetector}-y.
 * <p>
 * Przepuszcza każdy pakiet przez komplet detektorów; gdy któryś zgłosi anomalię,
 * oznacza pakiet i dopisuje opis, a także zlicza wystąpienia poszczególnych typów
 * anomalii na potrzeby raportu (suma kontrolna celowo nie jest zliczana).
 */
public class AnomalyEngine {
    private final List<AnomalyDetector> detectors;
    private final Map<String, Integer> anomalyCount= new HashMap<>();
    /**
     * @param detectors lista detektorów uruchamianych dla każdego pakietu
     */
    public AnomalyEngine(List<AnomalyDetector> detectors) {this.detectors = detectors;}

    /**
     * Bada pakiet wszystkimi detektorami i odnotowuje wykryte anomalie.
     *
     * @param packet przeanalizowany pakiet (zostanie oznaczony przy wykryciu anomalii)
     * @param raw    surowy pakiet pcap4j
     * @param nowMs  znacznik czasu pakietu w milisekundach
     */
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

    /** Wywołuje czyszczenie stanu we wszystkich detektorach. */
    public void evictIdle(long nowMs) { detectors.forEach(d -> d.evictIdle(nowMs)); }

    /** @return niemodyfikowalna mapa: nazwa anomalii → liczba wystąpień. */
    public Map<String, Integer> getAnomalyCount() {
        return Collections.unmodifiableMap(anomalyCount);
    }
}
