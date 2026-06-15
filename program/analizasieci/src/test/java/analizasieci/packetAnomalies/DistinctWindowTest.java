package analizasieci.packetAnomalies;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Testy {@link DistinctWindow} – czasowego okna liczącego UNIKALNE wartości
 * (np. liczbę różnych portów docelowych przy wykrywaniu skanowania portów).
 */
@DisplayName("DistinctWindow")
class DistinctWindowTest {

    @Test
    void countsUniqueValues() {
        DistinctWindow<String> w = new DistinctWindow<>(1000);
        assertEquals(1, w.add("a", 1000));
        assertEquals(2, w.add("b", 1100));
        assertEquals(2, w.add("a", 1200));
    }

    @Test
    void removesValuesOutOfTheWindow() {
        DistinctWindow<String> w = new DistinctWindow<>(1000);
        w.add("a", 1000);
        w.add("b", 1100);
        assertEquals(0, w.prune(2200));
    }

    @Test
    void valueRefreshExtendsLifetime() {
        DistinctWindow<String> w = new DistinctWindow<>(1000);
        w.add("a", 1000);
        w.add("a", 1900);
        assertEquals(1, w.prune(2200));
    }

    @Test
    void isEmptyProperState() {
        DistinctWindow<String> w = new DistinctWindow<>(100);
        assertTrue(w.isEmpty());
        w.add("x", 50);
        assertFalse(w.isEmpty());
        w.prune(1000);
        assertTrue(w.isEmpty());
    }
}
