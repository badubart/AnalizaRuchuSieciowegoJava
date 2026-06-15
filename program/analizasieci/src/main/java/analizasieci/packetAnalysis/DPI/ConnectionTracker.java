package analizasieci.packetAnalysis.DPI.protocolMatchers;

import analizasieci.packetCapture.packetLayers.ProtocolLayer;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Śledzi połączenia i klasyfikuje ich protokół aplikacyjny (DPI w kontekście strumienia).
 * <p>
 * Dla każdego {@link ConnectionKey} zapamiętuje raz rozpoznany protokół,
 * dzięki czemu kolejne pakiety tego samego strumienia są spójnie klasyfikowane nawet,
 * gdy nie powtarzają sygnatury. Jeśli po {@code MAX_PROBES} pakietach nic nie pasuje,
 * dla danego połączenia rezygnuje z dalszych prób. Stan jest współdzielony między
 * wątkami ({@link ConcurrentHashMap}).
 */
public class ConnectionTracker {
    private static final int MAX_PROBES = 8;   // ile pakietów próbujemy, zanim odpuścimy
    private final Map<ConnectionKey, ConnectionState> connections = new ConcurrentHashMap<>();
    private final List<ProtocolMatcher> matchers;

    /**
     * @param matchers lista matcherów protokołów sprawdzanych przy klasyfikacji
     */
    public ConnectionTracker(List<ProtocolMatcher> matchers) { this.matchers = matchers; }

    private static final class ConnectionState {
        ProtocolMatcher matcher;
        int probes;
        boolean giveUp;
        long lastSeenMs = System.currentTimeMillis();
    }

    /**
     * Wynik klasyfikacji: dopasowany matcher oraz zbudowana warstwa protokołu.
     *
     * @param matcher rozpoznany matcher protokołu
     * @param layer   warstwa zbudowana dla tego pakietu (główna lub kontynuacyjna)
     */
    public record Result(ProtocolMatcher matcher, ProtocolLayer layer) {}

    /**
     * Klasyfikuje pakiet w kontekście jego połączenia.
     *
     * @param key     znormalizowany klucz połączenia
     * @param payload ładunek warstwy aplikacji
     * @param srcPort port źródłowy
     * @param dstPort port docelowy
     * @param overTcp {@code true} dla TCP, {@code false} dla UDP
     * @return wynik z rozpoznanym protokołem lub {@code null}, gdy nie udało się rozpoznać
     */
    public Result classify(ConnectionKey key, byte[] payload, int srcPort, int dstPort, boolean overTcp) {
        ConnectionState st = connections.computeIfAbsent(key, k -> new ConnectionState());
        st.lastSeenMs = System.currentTimeMillis();

        if (st.matcher != null) {
            ProtocolMatcher m = st.matcher;
            ProtocolLayer layer = m.identify(payload, srcPort, dstPort, overTcp)
                    ? m.createLayer(payload, overTcp)
                    : m.createContinuationLayer(payload, overTcp);
            return new Result(m, layer);
        }
        if (st.giveUp) return null;

        ProtocolMatcher hit = match(payload, srcPort, dstPort, overTcp);
        if (hit != null) {
            st.matcher = hit;
            return new Result(hit, hit.createLayer(payload, overTcp));
        }

        if (++st.probes >= MAX_PROBES) st.giveUp = true;
        return null;
    }

    private ProtocolMatcher match(byte[] p, int srcPort, int dstPort, boolean overTcp) {
        return matchers.stream()
                .filter(m -> m.isTcp(overTcp))
                .sorted(Comparator.comparingInt(m -> m.isDefaultPort(srcPort, dstPort) ? 0 : 1))
                .filter(m -> m.identify(p, srcPort, dstPort, overTcp))
                .findFirst()
                .orElse(null);
    }

    /**
     * Usuwa połączenia nieaktywne dłużej niż podany czas (zwalnianie pamięci).
     *
     * @param idleMs maksymalny dozwolony czas bezczynności w milisekundach
     */
    public void evictIdle(long idleMs) {
        long cutoff = System.currentTimeMillis() - idleMs;
        connections.entrySet().removeIf(e -> e.getValue().lastSeenMs < cutoff);
    }
    /** Usuwa pojedyncze połączenie o podanym kluczu. */
    public void remove(ConnectionKey key) { connections.remove(key); }
}
