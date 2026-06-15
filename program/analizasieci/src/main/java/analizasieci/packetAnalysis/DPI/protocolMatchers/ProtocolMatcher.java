package analizasieci.packetAnalysis.DPI.protocolMatchers;

import analizasieci.packetCapture.packetLayers.ProtocolLayer;
import analizasieci.packetCapture.packetLayers.RawData;

import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * Bazowa klasa wzorca rozpoznawania protokołu warstwy aplikacji (DPI).
 * <p>
 * Każdy protokół (HTTP, FTP, TLS, ...) implementuje własny matcher dziedziczący
 * po tej klasie i decyduje na podstawie danych (oraz portów), czy dany pakiet
 * należy do tego protokołu ({@link #identify}) oraz jak zbudować jego warstwę
 * ({@link #createLayer}). Klasa udostępnia też wspólne metody pomocnicze do
 * porównywania bajtów oraz informacje o portach domyślnych i warstwie transportowej.
 */
public abstract class ProtocolMatcher {
    /** Warstwa transportowa, nad którą działa protokół: TCP, UDP lub obie. */
    public enum L4Protocol { TCP, UDP, BOTH}
    private final String name;
    private final L4Protocol transportProtocol;
    private final Set<Integer> defaultPorts;

    protected ProtocolMatcher(String name, L4Protocol transportProtocol, Integer... defaultPorts) {
        this.name = name;
        this.transportProtocol = transportProtocol;
        this.defaultPorts = Set.of(defaultPorts);
    }
    /** @return nazwa protokołu (np. "HTTP"). */
    public String getName() {
        return name;
    }
    /** @return {@code true}, gdy port źródłowy lub docelowy jest portem domyślnym tego protokołu. */
    public boolean isDefaultPort(int srcPort, int dstPort) {
        return  defaultPorts.contains(srcPort) || defaultPorts.contains(dstPort);
    }
    /**
     * Sprawdza zgodność warstwy transportowej pakietu z tym protokołem.
     *
     * @param overTcp {@code true}, gdy pakiet jest przenoszony przez TCP (inaczej UDP)
     * @return {@code true}, gdy protokół obsługuje tę warstwę (TCP, UDP lub BOTH)
     */
    public boolean isTcp(boolean overTcp){
        return transportProtocol == L4Protocol.BOTH || (transportProtocol == L4Protocol.TCP) == overTcp;
    }
    /** @return warstwa transportowa, nad którą działa protokół. */
    public L4Protocol getTransportProtocol() {
        return transportProtocol;
    }

    /**
     * Decyduje, czy ładunek należy do tego protokołu (sygnatura, prefiks tekstowy itp.).
     *
     * @param payload bajty ładunku warstwy aplikacji
     * @param srcPort port źródłowy
     * @param dstPort port docelowy
     * @param overTcp {@code true} dla TCP, {@code false} dla UDP
     * @return {@code true}, gdy ładunek pasuje do tego protokołu
     */
    public abstract boolean identify(byte[] payload, int srcPort, int dstPort, boolean overTcp);

    /**
     * Buduje warstwę protokołu na podstawie rozpoznanego ładunku.
     *
     * @param payload bajty ładunku warstwy aplikacji
     * @param overTcp {@code true} dla TCP, {@code false} dla UDP
     * @return warstwa {@link ProtocolLayer} reprezentująca ten protokół
     */
    public abstract ProtocolLayer createLayer(byte[] payload, boolean overTcp);

    /** Pomocnicze: czy bajty {@code p} zaczynają się od podanego ciągu ASCII. */
    protected static boolean startsWith(byte[] p, String ascii) {
        byte[] s = ascii.getBytes(StandardCharsets.US_ASCII);
        if (p.length < s.length) return false;
        for (int i = 0; i < s.length; i++) if (p[i] != s[i]) return false;
        return true;
    }
    protected static boolean startsWithAny(byte[] p, String... prefixes) { // sprawdza czy payload zaczyna sie od któregoś z prefixów (użyteczne dla np. HTTP, SMTP i innych tekstowych)
        for (String s : prefixes) if (startsWith(p, s)) return true;
        return false;
    }
    protected static boolean eq(byte[] p, int off, int... bytes) { // sprawdza czy bity od jakiegos momentu sa rowne danym w argumentach
        if (p.length < off + bytes.length) return false;
        for (int i = 0; i < bytes.length; i++)
            if ((p[off + i] & 0xFF) != (bytes[i] & 0xFF)) return false;
        return true;
    }
    /** Pomocnicze: czy bajt jest cyfrą ASCII (0-9). */
    protected static boolean isDigit(byte b) { return b >= '0' && b <= '9'; }

    /**
     * Nazwa sesji prezentowana w UI – domyślnie nazwa protokołu.
     * Podklasy mogą ją uściślić na podstawie portu (np. TLS: 443 → "HTTPS").
     */
    public String getSessionName(int srcPort, int dstPort) { return getName(); }

    /** @return protokół aplikacyjny rozpoznany po porcie lub {@code null}, gdy nieznany. */
    public String getApplicationProtocol(int srcPort, int dstPort) { return null; }
    /**
     * Warstwa dla kolejnych pakietów już rozpoznanego strumienia,
     * gdy ładunek nie zawiera ponownie sygnatury – domyślnie surowe dane.
     */
    public ProtocolLayer createContinuationLayer(byte[] p, boolean overTcp) { return new RawData(p); }
}
