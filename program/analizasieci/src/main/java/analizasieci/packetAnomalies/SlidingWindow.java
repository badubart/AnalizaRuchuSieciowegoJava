package analizasieci.packetAnomalies;

import java.util.ArrayDeque;

/**
 * Przesuwne okno czasowe zliczające zdarzenia z ostatnich {@code windowMs} milisekund.
 * <p>
 * Wykorzystywane przy wykrywaniu anomalii zależnych od częstotliwości (np. DoS/DDoS,
 * skanowanie). Zdarzenia starsze niż okno są usuwane przy każdej operacji.
 */
public final class SlidingWindow {
    private final long windowMs;
    private final ArrayDeque<Long> events = new ArrayDeque<>();
    /**
     * @param windowMs długość okna w milisekundach
     */
    public SlidingWindow(long windowMs) { this.windowMs = windowMs; }
    /**
     * Dodaje zdarzenie ze znacznikiem czasu {@code now} i czyści przeterminowane.
     *
     * @param now znacznik czasu zdarzenia (ms)
     * @return liczba zdarzeń w aktualnym oknie
     */
    public int add(long now) { events.addLast(now); return prune(now); }
    /**
     * Usuwa zdarzenia starsze niż {@code now - windowMs}.
     *
     * @param now bieżący znacznik czasu (ms)
     * @return liczba zdarzeń pozostałych w oknie
     */
    public int prune(long now) {
        long cutoff = now - windowMs;
        while (!events.isEmpty() && events.peekFirst() < cutoff) events.removeFirst();
        return events.size();
    }
    /** @return {@code true}, gdy w oknie nie ma żadnych zdarzeń. */
    public boolean isEmpty() { return events.isEmpty(); }
}