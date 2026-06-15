package analizasieci.packetAnomalies;

import java.util.HashMap;

/**
 * Przesuwne okno czasowe zliczające UNIKALNE wartości widziane w ostatnich
 * {@code windowMs} milisekundach.
 * <p>
 * Każda wartość pamięta tylko czas ostatniego wystąpienia, więc jej powtórzenie
 * jedynie odświeża wpis (nie zwiększa licznika). Przydatne np. do liczenia różnych
 * portów docelowych przy wykrywaniu skanowania portów.
 *
 * @param <T> typ zliczanej wartości (np. numer portu, adres)
 */
public final class DistinctWindow<T> {
    private final long windowMs;
    private final HashMap<T, Long> lastSeen = new HashMap<>();
    /**
     * @param windowMs długość okna w milisekundach
     */
    public DistinctWindow(long windowMs) { this.windowMs = windowMs; }
    /**
     * Zapisuje (lub odświeża) wartość i czyści przeterminowane wpisy.
     *
     * @param v   wartość do zliczenia
     * @param now znacznik czasu wystąpienia (ms)
     * @return liczba unikalnych wartości w aktualnym oknie
     */
    public int add(T v, long now) { lastSeen.put(v, now); return prune(now); }
    /**
     * Usuwa wartości, których ostatnie wystąpienie jest starsze niż {@code now - windowMs}.
     *
     * @param now bieżący znacznik czasu (ms)
     * @return liczba unikalnych wartości pozostałych w oknie
     */
    public int prune(long now) {
        long cutoff = now - windowMs;
        lastSeen.values().removeIf(t -> t < cutoff);
        return lastSeen.size();
    }
    /** @return {@code true}, gdy w oknie nie ma żadnej wartości. */
    public boolean isEmpty() { return lastSeen.isEmpty(); }
}