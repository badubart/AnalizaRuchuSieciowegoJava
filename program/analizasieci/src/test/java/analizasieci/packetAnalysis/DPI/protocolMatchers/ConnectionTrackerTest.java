package analizasieci.packetAnalysis.DPI.protocolMatchers;

import analizasieci.packetCapture.packetLayers.L7HTTP;
import analizasieci.packetCapture.packetLayers.RawData;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Testy {@link ConnectionTracker} – klasyfikacji protokołu w obrębie połączenia:
 * pierwszego dopasowania, "lepkości" (zapamiętanie protokołu), braku dopasowania
 * oraz rezygnacji po wyczerpaniu prób (MAX_PROBES).
 */
@DisplayName("ConnectionTracker")
class ConnectionTrackerTest {

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private ConnectionTracker newTracker() {
        return new ConnectionTracker(List.of(new HttpMatcher(), new SshMatcher(), new FtpMatcher()));
    }

    @Test
    void classifyHttpFirstPacket() {
        ConnectionTracker t = newTracker();
        ConnectionKey key = ConnectionKey.of("10.0.0.1", 50000, "10.0.0.2", 80, true);

        ConnectionTracker.Result r = t.classify(key, ascii("GET / HTTP/1.1\r\n"), 50000, 80, true);

        assertNotNull(r);
        assertEquals("HTTP", r.matcher().getName());
        assertInstanceOf(L7HTTP.class, r.layer());
    }

    @Test
    void rememberProtocolForConnection() {
        ConnectionTracker t = newTracker();
        ConnectionKey key = ConnectionKey.of("10.0.0.1", 50000, "10.0.0.2", 80, true);

        t.classify(key, ascii("GET / HTTP/1.1\r\n"), 50000, 80, true); // ustala protokół = HTTP

        // kolejny pakiet bez nagłówka HTTP – nadal należy do tego samego (HTTP) połączenia
        ConnectionTracker.Result cont = t.classify(key, ascii("losowe-dane-bez-naglowka"), 50000, 80, true);

        assertNotNull(cont);
        assertEquals("HTTP", cont.matcher().getName());
        assertInstanceOf(RawData.class, cont.layer()); // warstwa kontynuacji
    }

    @Test
    void returnsNullOnNoLink() {
        ConnectionTracker t = newTracker();
        ConnectionKey key = ConnectionKey.of("10.0.0.1", 50000, "10.0.0.2", 9999, true);

        assertNull(t.classify(key, ascii("cokolwiek-nieznanego"), 50000, 9999, true));
    }

    @Test
    void resignsAfterTreshold() {
        ConnectionTracker t = newTracker();
        ConnectionKey key = ConnectionKey.of("10.0.0.1", 50000, "10.0.0.2", 9999, true);
        byte[] nieznane = ascii("dane-ktore-nie-pasuja");

        for (int i = 0; i < 8; i++) { // MAX_PROBES = 8
            assertNull(t.classify(key, nieznane, 50000, 9999, true));
        }
        // po rezygnacji nawet poprawny ładunek HTTP nie zostanie już rozpoznany w tym połączeniu
        assertNull(t.classify(key, ascii("GET / HTTP/1.1\r\n"), 50000, 9999, true));
    }
}
