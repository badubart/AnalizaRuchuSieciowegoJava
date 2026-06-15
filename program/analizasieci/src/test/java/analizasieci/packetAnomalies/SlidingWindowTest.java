package analizasieci.packetAnomalies;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Testy {@link SlidingWindow} – czasowego okna liczącego zdarzenia
 * (używanego m.in. do wykrywania DoS/DDoS, skanowania portów itp.).
 */
@DisplayName("SlidingWindow")
class SlidingWindowTest {

    @Test
    void countsOccurencesInWindow() {
        SlidingWindow w = new SlidingWindow(1000);
        assertEquals(1, w.add(1000));
        assertEquals(2, w.add(1500)); // oba mieszczą się w oknie 1000 ms
    }

    @Test
    void deletesOldOcurrences() {
        SlidingWindow w = new SlidingWindow(1000);
        w.add(1000);
        w.add(1500);
        assertEquals(1, w.add(2600)); // odcięcie = 1600, zostaje tylko zdarzenie z 2600
    }

    @Test
    void properWindowBoundaries() {
        SlidingWindow w = new SlidingWindow(1000);
        w.add(0);
        assertEquals(2, w.add(1000)); // 0 dokładnie na granicy (odcięcie=0, 0<0 fałsz) -> zostaje
        assertEquals(2, w.add(1001)); // odcięcie=1, zdarzenie 0 wypada, zostają 1000 i 1001
    }

    @Test
    void isEmptyProperState() {
        SlidingWindow w = new SlidingWindow(100);
        assertTrue(w.isEmpty());
        w.add(50);
        assertFalse(w.isEmpty());
        w.prune(1000); // wszystko już poza oknem
        assertTrue(w.isEmpty());
    }
}
