package analizasieci.packetAnalysis.DPI.protocolMatchers;

import analizasieci.packetCapture.packetLayers.L7SMTP;
import analizasieci.packetCapture.packetLayers.ProtocolLayer;

import java.nio.charset.StandardCharsets;

/**
 * Matcher protokołu SMTP (TCP, porty 25/587/465).
 * Rozpoznaje komendy (HELO, EHLO, MAIL FROM, ...) oraz powitanie "220" zawierające "SMTP".
 */
public class SmtpMatcher  extends ProtocolMatcher{
    public SmtpMatcher() { super("SMTP", L4Protocol.TCP, 25, 587, 465); }
    @Override public boolean identify(byte[] p, int s, int d, boolean tcp) {
        if (startsWithAny(p, "HELO ", "EHLO ", "MAIL FROM", "RCPT TO", "DATA")) return true;
        if (startsWith(p, "220")) {
            String head = new String(p, 0, Math.min(p.length, 128),
                    StandardCharsets.US_ASCII).toUpperCase();
            return head.contains("SMTP");
        }
        return false;
    }
    @Override public ProtocolLayer createLayer(byte[] p, boolean tcp) {
        return new L7SMTP(p);
    }
}
