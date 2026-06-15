package analizasieci.packetAnalysis.DPI.protocolMatchers;

import analizasieci.packetCapture.packetLayers.L7HTTP;
import analizasieci.packetCapture.packetLayers.ProtocolLayer;

import java.nio.charset.StandardCharsets;

/**
 * Matcher protokołu HTTP (TCP, porty 80/8080/8000).
 * Rozpoznaje żądania po metodach (GET, POST, ...) oraz odpowiedzi po prefiksie "HTTP/".
 */
public class HttpMatcher  extends ProtocolMatcher{
    public HttpMatcher() { super("HTTP", L4Protocol.TCP, 80, 8080, 8000); }
    @Override public boolean identify(byte[] p, int s, int d, boolean tcp) {
        return startsWithAny(p, "GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
                "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ")
                || startsWith(p, "HTTP/"); // protokół tekstowy, łatwo sprawdzić - odpowiednie instrukcje
    }
    @Override public ProtocolLayer createLayer(byte[] p, boolean tcp) {
        return new L7HTTP(new String(p, StandardCharsets.UTF_8));
    }
}
