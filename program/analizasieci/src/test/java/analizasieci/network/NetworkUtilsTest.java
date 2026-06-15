package analizasieci.network;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test {@link NetworkUtils#getLocalIpv4Address()}.
 * Wynik zależy od środowiska, więc sprawdzamy niezmiennik: zwracany jest
 * niepusty, poprawny składniowo adres IPv4 (realny lub fallback 127.0.0.1).
 */
@DisplayName("NetworkUtils")
class NetworkUtilsTest {

    @Test
    void returnsProperIPV4() {
        String ip = NetworkUtils.getLocalIpv4Address();

        assertNotNull(ip);
        assertFalse(ip.isBlank());

        String[] octets = ip.split("\\.");
        assertEquals(4, octets.length, "Adres IPv4 powinien mieć 4 oktety, otrzymano: " + ip);
        for (String octet : octets) {
            int value = Integer.parseInt(octet);
            assertTrue(value >= 0 && value <= 255, "Oktet poza zakresem 0-255: " + octet);
        }
    }
}
