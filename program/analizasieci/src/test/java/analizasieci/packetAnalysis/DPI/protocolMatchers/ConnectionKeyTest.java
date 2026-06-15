package analizasieci.packetAnalysis.DPI.protocolMatchers;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
//import analizasieci.packetAnalysis.DPI.protocolMatchers.ConnectionKey;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Testy normalizacji klucza połączenia {@link ConnectionKey}.
 * Klucz musi być symetryczny – ten sam strumień opisany "w drugą stronę"
 * (zamienione adresy/porty) powinien dawać identyczny klucz.
 */
@DisplayName("ConnectionKey")
class ConnectionKeyTest {

    @Test
    void keyIsSymetrical() {
        ConnectionKey a = ConnectionKey.of("1.1.1.1", 100, "2.2.2.2", 200, true);
        ConnectionKey b = ConnectionKey.of("2.2.2.2", 200, "1.1.1.1", 100, true);

        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());

        // normalizacja: "niższy" adres trafia na pozycję low
        assertEquals("1.1.1.1", a.ipLow());
        assertEquals(100, a.portLow());
        assertEquals("2.2.2.2", a.ipHigh());
        assertEquals(200, a.portHigh());
    }

    @Test
    void equalAdressesDifferentPort() {
        ConnectionKey k = ConnectionKey.of("1.1.1.1", 200, "1.1.1.1", 100, true);
        assertEquals(100, k.portLow());
        assertEquals(200, k.portHigh());
    }

    @Test
    void differentL4Protocols() {
        ConnectionKey tcp = ConnectionKey.of("1.1.1.1", 100, "2.2.2.2", 200, true);
        ConnectionKey udp = ConnectionKey.of("1.1.1.1", 100, "2.2.2.2", 200, false);
        assertNotEquals(tcp, udp);
    }
}
