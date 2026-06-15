package analizasieci.packetAnalysis.DPI.protocolMatchers;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Testy rozpoznawania protokołów (Deep Packet Inspection).
 * Sprawdzają metodę {@code identify(...)} każdego matchera na typowych ładunkach
 * pozytywnych i negatywnych. To czysta logika na tablicach bajtów – bez sieci i pcap.
 */
@DisplayName("identyfikacja protokołów")
class ProtocolMatchersTest {

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    // ------------------------------- HTTP -------------------------------
    @Test
    void httpRecognition() {
        HttpMatcher m = new HttpMatcher();
        assertTrue(m.identify(ascii("GET /index.html HTTP/1.1\r\n"), 50000, 80, true));
        assertTrue(m.identify(ascii("POST /api HTTP/1.1\r\n"), 50000, 80, true));
        assertTrue(m.identify(ascii("HTTP/1.1 200 OK\r\n"), 80, 50000, true));
    }

    @Test
    void httpDeniesUnreatedInstructions() {
        HttpMatcher m = new HttpMatcher();
        assertFalse(m.identify(ascii("SSH-2.0-OpenSSH\r\n"), 50000, 22, true));
        assertFalse(m.identify(ascii("GETX"), 1, 2, true)); // brak spacji po metodzie
        assertFalse(m.identify(new byte[0], 1, 2, true));
    }

    // ------------------------------- FTP --------------------------------
    @Test
    void ftpRecognizesCommands() {
        FtpMatcher m = new FtpMatcher();
        assertTrue(m.identify(ascii("220 Welcome\r\n"), 21, 50000, true)); // kod + spacja
        assertTrue(m.identify(ascii("220-Multiline banner\r\n"), 21, 50000, true)); // kod + '-'
        assertTrue(m.identify(ascii("USER anonymous\r\n"), 50000, 21, true));
    }

    @Test
    void ftpDiscardsWrongCommands() {
        FtpMatcher m = new FtpMatcher();
        assertFalse(m.identify(ascii("HELLO there\r\n"), 1, 2, true));
        assertFalse(m.identify(ascii("22 X"), 1, 2, true)); // tylko 2 cyfry
    }

    // ------------------------------- SSH --------------------------------
    @Test
    void sshRecognizesBanner() {
        SshMatcher m = new SshMatcher();
        assertTrue(m.identify(ascii("SSH-2.0-OpenSSH_8.9\r\n"), 50000, 22, true));
        assertFalse(m.identify(ascii("GET / HTTP/1.1"), 1, 2, true));
    }

    // ------------------------------- TLS --------------------------------
    @Test
    void tlsRecognizesClientHelloAndServerHello() {
        TlsMatcher m = new TlsMatcher();
        // ContentType=0x16(handshake), wersja 0x03 0x01, [5]=0x01 ClientHello
        byte[] clientHello = {0x16, 0x03, 0x01, 0x00, 0x2f, 0x01};
        assertTrue(m.identify(clientHello, 50000, 443, true));
        // [5]=0x02 ServerHello (serwer jako źródło)
        byte[] serverHello = {0x16, 0x03, 0x03, 0x00, 0x2f, 0x02};
        assertTrue(m.identify(serverHello, 443, 50000, true));
    }

    @Test
    void tlsDiscardsTooShortAndWrongTypes() {
        TlsMatcher m = new TlsMatcher();
        assertFalse(m.identify(new byte[]{0x16, 0x03, 0x01, 0x00, 0x00}, 1, 2, true)); // < 6 bajtów
        assertFalse(m.identify(new byte[]{0x17, 0x03, 0x01, 0x00, 0x00, 0x01}, 1, 2, true)); // typ != 0x16
    }

    @Test
    void tlsMapsPorts() {
        TlsMatcher m = new TlsMatcher();
        assertEquals("HTTPS", m.getSessionName(50000, 443));
        assertEquals("HTTPS", m.getSessionName(443, 50000)); // serwer jako źródło
        assertEquals("HTTPS", m.getApplicationProtocol(50000, 443));
        assertEquals("TLS", m.getSessionName(1111, 2222));   // nieznana usługa
        assertNull(m.getApplicationProtocol(1111, 2222));
    }

    // ------------------------------- SMTP -------------------------------
    @Test
    void smtpRecogniesCommands() {
        SmtpMatcher m = new SmtpMatcher();
        assertTrue(m.identify(ascii("EHLO example.com\r\n"), 50000, 25, true));
        assertTrue(m.identify(ascii("220 mail.example.com ESMTP Postfix\r\n"), 25, 50000, true));
    }

    @Test
    void smtpEdgeCaseNoSMTPInPayload() {
        SmtpMatcher m = new SmtpMatcher();
        // zaczyna się od "220", ale w treści nie ma "SMTP" -> to nie SMTP
        assertFalse(m.identify(ascii("220 FTP Server ready\r\n"), 1, 2, true));
    }

    // ------------------------------ Telnet ------------------------------
    @Test
    void telnetRecognizesNegotiations() {
        TelnetMatcher m = new TelnetMatcher();
        assertTrue(m.identify(new byte[]{(byte) 0xFF, (byte) 0xFB, 0x01}, 50000, 23, true)); // IAC WILL ECHO
        assertFalse(m.identify(new byte[]{(byte) 0xFF, 0x01, 0x02}, 1, 2, true)); // 2. bajt poza 0xFB..0xFE
        assertFalse(m.identify(new byte[]{(byte) 0xFF, (byte) 0xFB}, 1, 2, true)); // za krótkie
    }

    // ------------------------------- DHCP -------------------------------
    @Test
    void dhcpRecognizesMagicCookie() {
        DhcpMatcher m = new DhcpMatcher();
        byte[] p = new byte[240];
        p[0] = 1; // op = BOOTREQUEST
        p[236] = (byte) 0x63;
        p[237] = (byte) 0x82;
        p[238] = (byte) 0x53;
        p[239] = (byte) 0x63;
        assertTrue(m.identify(p, 68, 67, false));
    }

    @Test
    void dhcpDiscardsNoCookieOrTooShort() {
        DhcpMatcher m = new DhcpMatcher();
        assertFalse(m.identify(new byte[240], 68, 67, false)); // brak cookie
        assertFalse(m.identify(new byte[100], 68, 67, false)); // za krótkie
    }

    // ------------------------------- SMB --------------------------------
    @Test
    void smbRecognizesProperPorts() {
        SmbMatcher m = new SmbMatcher();
        byte[] direct = {(byte) 0xFF, 'S', 'M', 'B', 0, 0, 0, 0};        // port 445, offset 0
        assertTrue(m.identify(direct, 50000, 445, true));
        byte[] netbios = {0, 0, 0, 0, (byte) 0xFE, 'S', 'M', 'B', 0};    // port 139, offset 4 (SMB2)
        assertTrue(m.identify(netbios, 50000, 139, true));
        assertFalse(m.identify(new byte[]{0, 1, 2, 3}, 50000, 445, true));
    }

    // ------------------------------- RPC --------------------------------
    @Test
    void rpcRecognizesCallReply2() {
        RpcMatcher m = new RpcMatcher();
        byte[] p = new byte[12];   // UDP -> offset 0
        p[11] = 2;                 // rpcVers (offset 8..11) = 2; msgType (4..7) = 0 (CALL)
        assertTrue(m.identify(p, 50000, 111, false));
        p[7] = 1;                  // msgType = 1 (REPLY)
        assertTrue(m.identify(p, 50000, 111, false));
    }

    @Test
    void rpcDiscardsWrongVersionOrLength() {
        RpcMatcher m = new RpcMatcher();
        byte[] p = new byte[12];
        p[11] = 3;                 // wersja RPC = 3 (niewspierana)
        assertFalse(m.identify(p, 50000, 111, false));
        assertFalse(m.identify(new byte[8], 50000, 111, false)); // < 12 bajtów
    }
}
