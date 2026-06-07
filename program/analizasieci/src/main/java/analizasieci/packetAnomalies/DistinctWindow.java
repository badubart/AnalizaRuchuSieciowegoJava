package analizasieci.packetAnomalies;

import java.util.HashMap;

public final class DistinctWindow<T> {
    private final long windowMs;
    private final HashMap<T, Long> lastSeen = new HashMap<>();
    public DistinctWindow(long windowMs) { this.windowMs = windowMs; }
    public int add(T v, long now) { lastSeen.put(v, now); return prune(now); }
    public int prune(long now) {
        long cutoff = now - windowMs;
        lastSeen.values().removeIf(t -> t < cutoff);
        return lastSeen.size();
    }
    public boolean isEmpty() { return lastSeen.isEmpty(); }
}