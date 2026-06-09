package analizasieci.packetAnomalies;

import java.util.ArrayDeque;

public final class SlidingWindow {
    private final long windowMs;
    private final ArrayDeque<Long> events = new ArrayDeque<>();
    public SlidingWindow(long windowMs) { this.windowMs = windowMs; }
    public int add(long now) { events.addLast(now); return prune(now); }
    public int prune(long now) {
        long cutoff = now - windowMs;
        while (!events.isEmpty() && events.peekFirst() < cutoff) events.removeFirst();
        return events.size();
    }
    public boolean isEmpty() { return events.isEmpty(); }
}