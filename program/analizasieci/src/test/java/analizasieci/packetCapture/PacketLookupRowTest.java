package analizasieci.packetCapture;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test modelu wiersza tabeli {@link PacketLookupRow} – sprawdza, że gettery
 * (wykorzystywane przez UI oraz mechanizm filtrowania) zwracają wartości
 * przekazane w konstruktorze.
 */
@DisplayName("PacketLookupRow")
class PacketLookupRowTest {

    @Test
    void gettersReturnProperValues() {
        PacketLookupRow row = new PacketLookupRow(
                7, 1024L,
                "192.168.0.10", "192.168.0.20",
                "HTTP", 512, "12:00:00", "GET /",
                "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", true);

        assertEquals(7, row.getId());
        assertEquals(1024L, row.getFileOffset());
        assertEquals("192.168.0.10", row.getSource());
        assertEquals("192.168.0.20", row.getDestination());
        assertEquals("HTTP", row.getProtocol());
        assertEquals(512, row.getLength());
        assertEquals("GET /", row.getInfo());
        assertEquals("AA:BB:CC:DD:EE:FF", row.getSourceMAC());
        assertEquals("11:22:33:44:55:66", row.getDestinationMAC());
        assertTrue(row.isAnomaly());
    }

    @Test
    void handlesNullValues() {
        PacketLookupRow row = new PacketLookupRow(
                0, 0L, null, null, null, 0, null, null, null, null, false);

        assertNull(row.getSource());
        assertNull(row.getDestination());
        assertNull(row.getProtocol());
        assertNull(row.getInfo());
        assertFalse(row.isAnomaly());
    }
}
