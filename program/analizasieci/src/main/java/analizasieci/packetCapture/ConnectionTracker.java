package analizasieci.packetCapture;

import analizasieci.packetCapture.packetLayers.ProtocolLayer;
import analizasieci.packetCapture.packetLayers.RawData;
import analizasieci.packetCapture.packetLayers.protocolMatchers.ProtocolMatcher;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ConnectionTracker {
    private static final int MAX_PROBES = 8;   // ile pakietów próbujemy, zanim odpuścimy
    private final Map<ConnectionKey, ConnectionState> connections = new ConcurrentHashMap<>();
    private final List<ProtocolMatcher> matchers;

    public ConnectionTracker(List<ProtocolMatcher> matchers) { this.matchers = matchers; }

    public record Result(ProtocolMatcher matcher, ProtocolLayer layer) {}

    private static final class ConnectionState {
        ProtocolMatcher matcher;
        int probes;
        boolean giveUp;
        long lastSeenMs = System.currentTimeMillis();
    }

    public Result classify(ConnectionKey key, byte[] payload, int srcPort, int dstPort, boolean overTcp) {
        ConnectionState st = connections.computeIfAbsent(key, k -> new ConnectionState());
        st.lastSeenMs = System.currentTimeMillis();

        if (st.matcher != null) {
            ProtocolLayer layer = st.matcher.identify(payload, srcPort, dstPort, overTcp)
                    ? st.matcher.createLayer(payload, overTcp)
                    : new RawData(payload);
            return new Result(st.matcher, layer);
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

    public void evictIdle(long idleMs) {
        long cutoff = System.currentTimeMillis() - idleMs;
        connections.entrySet().removeIf(e -> e.getValue().lastSeenMs < cutoff);
    }
}
