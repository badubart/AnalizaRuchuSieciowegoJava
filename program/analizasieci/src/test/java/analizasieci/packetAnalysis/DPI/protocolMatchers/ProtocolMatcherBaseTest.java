package analizasieci.packetAnalysis.DPI.protocolMatchers;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Testy wspólnej logiki klasy bazowej {@link ProtocolMatcher}:
 * dopasowanie portu domyślnego oraz zgodność warstwy transportowej (TCP/UDP/BOTH).
 */
@DisplayName("logika bazowa matchera")
class ProtocolMatcherBaseTest {

    @Test
    void isDefaultPortChecksBothDirections() {
        HttpMatcher http = new HttpMatcher(); // porty domyślne: 80, 8080, 8000
        assertTrue(http.isDefaultPort(50000, 80));    // port docelowy domyślny
        assertTrue(http.isDefaultPort(8080, 50000));  // port źródłowy domyślny
        assertFalse(http.isDefaultPort(50000, 54321));
    }

    @Test
    void isTcpMatchesTransportLayer() {
        assertTrue(new HttpMatcher().isTcp(true));    // TCP nad TCP
        assertFalse(new HttpMatcher().isTcp(false));  // TCP nad UDP -> nie
        assertTrue(new DhcpMatcher().isTcp(false));   // UDP nad UDP
        assertFalse(new DhcpMatcher().isTcp(true));   // UDP nad TCP -> nie
        assertTrue(new RpcMatcher().isTcp(true));     // BOTH -> zawsze
        assertTrue(new RpcMatcher().isTcp(false));    // BOTH -> zawsze
    }

    @Test
    void getNameReturnsProtocolName() {
        assertEquals("HTTP", new HttpMatcher().getName());
        assertEquals("DHCP", new DhcpMatcher().getName());
        assertEquals("RPC", new RpcMatcher().getName());
    }
}
