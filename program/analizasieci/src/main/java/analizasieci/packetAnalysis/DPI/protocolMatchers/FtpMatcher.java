package analizasieci.packetAnalysis.DPI.protocolMatchers;

import analizasieci.packetCapture.packetLayers.L7FTP;
import analizasieci.packetCapture.packetLayers.ProtocolLayer;

import java.nio.charset.StandardCharsets;

/**
 * Matcher protokołu FTP (TCP, port 21).
 * Rozpoznaje 3-cyfrowe kody odpowiedzi (np. "220 ") oraz komendy klienta (USER, PASS, RETR, ...).
 */
public class FtpMatcher  extends ProtocolMatcher{
    public FtpMatcher() { super("FTP", L4Protocol.TCP, 21); }
    @Override public boolean identify(byte[] p, int s, int d, boolean tcp) {
        return replyCode(p) || startsWithAny(p, "USER ", "PASS ", "RETR ", "STOR ",
                "LIST", "QUIT", "CWD ", "PASV", "PORT ", "TYPE ");
    }
    private static boolean replyCode(byte[] p) {   // "220 " lub "220-"
        return p.length >= 4 && isDigit(p[0]) && isDigit(p[1]) && isDigit(p[2])
                && (p[3] == ' ' || p[3] == '-');
    }
    @Override public ProtocolLayer createLayer(byte[] p, boolean tcp) {
        return new L7FTP(new String(p, StandardCharsets.UTF_8));
    }
}
