package analizasieci.packetAnomalies;

import analizasieci.packetCapture.MyPacket;
import org.pcap4j.packet.Packet;

/**
 * Wspólny interfejs detektora anomalii.
 * <p>
 * Każda implementacja bada pojedynczy pakiet i zwraca opis wykrytej anomalii
 * lub {@code null}, gdy pakiet jest poprawny. Detektory mogą utrzymywać stan
 * (np. okna czasowe), który okresowo czyszczą w {@link #evictIdle(long)}.
 */
public interface AnomalyDetector {
    /** @return krótka nazwa typu anomalii (np. "DoS", "PortScan"). */
    String getName();

    /**
     * Bada pakiet pod kątem konkretnej anomalii.
     *
     * @param packet przeanalizowany pakiet (model aplikacji)
     * @param raw    surowy pakiet pcap4j (dostęp do nagłówków warstw)
     * @param nowMs  znacznik czasu pakietu w milisekundach
     * @return opis anomalii lub {@code null}, gdy jej nie wykryto
     */
    String inspect(MyPacket packet, Packet raw, long nowMs);

    /**
     * Czyści przeterminowany stan wewnętrzny (np. stare wpisy okien czasowych).
     * Domyślnie nic nie robi.
     *
     * @param nowMs bieżący znacznik czasu w milisekundach
     */
    default void evictIdle(long nowMs) {}
}
