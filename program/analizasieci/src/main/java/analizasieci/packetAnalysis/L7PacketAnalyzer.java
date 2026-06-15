package analizasieci.packetAnalysis;

import analizasieci.packetAnalysis.DPI.protocolMatchers.ConnectionKey;
import analizasieci.packetAnalysis.DPI.protocolMatchers.ConnectionTracker;
import analizasieci.packetCapture.MyPacket;
import analizasieci.packetCapture.packetLayers.RawData;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import analizasieci.packetAnalysis.DPI.protocolMatchers.*;

import java.util.List;

/**
 * Analizator warstwy aplikacji (L7) wykorzystujący DPI.
 * <p>
 * Utrzymuje listę matcherów protokołów oraz współdzielony {@link ConnectionTracker},
 * który klasyfikuje ładunek w kontekście całego połączenia. Wynik (nazwa protokołu
 * i warstwa) jest dopisywany do modelu {@link MyPacket}; gdy nic nie pasuje, dodawana
 * jest warstwa surowych danych.
 */
public class L7PacketAnalyzer {

    private static final List<ProtocolMatcher> MATCHERS = List.of(
            new HttpMatcher(),
            new TlsMatcher(),
            new SshMatcher(),
            new SmtpMatcher(),
            new FtpMatcher(),
            new TelnetMatcher(),
            new SmbMatcher(),
            new DhcpMatcher(),
            new RpcMatcher()
    );
    private static final ConnectionTracker tracker = new ConnectionTracker(MATCHERS);

    /**
     * Rozpoznaje protokół aplikacyjny ładunku i wzbogaca model pakietu.
     *
     * @param payload  bajty ładunku warstwy transportowej
     * @param l4Packet pakiet warstwy 4 (TCP lub UDP) – źródło portów
     * @param myPacket model pakietu do uzupełnienia o warstwę i nazwę protokołu
     */
    public static void analyze(byte[] payload, Packet l4Packet, MyPacket myPacket) {
        if (payload == null || payload.length == 0) return;

        int srcPort = -1, dstPort = -1;
        boolean overTcp = false;
        if (l4Packet instanceof TcpPacket tcp) {
            srcPort = tcp.getHeader().getSrcPort().valueAsInt();
            dstPort = tcp.getHeader().getDstPort().valueAsInt();
            overTcp = true;
        } else if (l4Packet instanceof UdpPacket udp) {
            srcPort = udp.getHeader().getSrcPort().valueAsInt();
            dstPort = udp.getHeader().getDstPort().valueAsInt();
        }

        ConnectionKey key = ConnectionKey.of(myPacket.getSourceIp(), srcPort, myPacket.getDestinationIp(), dstPort, overTcp);
        ConnectionTracker.Result r = tracker.classify(key, payload, srcPort, dstPort, overTcp);
        if (r != null) {
            myPacket.setHighestProtocolName(r.matcher().getName());   // "TLS"
            myPacket.addLayer(r.layer());

            String app = r.matcher().getApplicationProtocol(srcPort, dstPort);   // "HTTPS" lub null
            if (app != null) {
                String flags = myPacket.getInfo() == null ? "" : myPacket.getInfo().trim();
                myPacket.setInfo(flags.isEmpty() ? app : app + "  " + flags);
            }
        } else {
            myPacket.setHighestProtocolName((overTcp)?"TCP":"UDP");
            myPacket.addLayer(new RawData(payload));
        }
    }
    /** Usuwa z trackera połączenia bezczynne dłużej niż {@code idleMs}. */
    public static void evictIdleConnections(long idleMs) { tracker.evictIdle(idleMs); }

    /** Usuwa z trackera połączenie zamknięte (FIN/RST), aby zwolnić jego stan. */
    public static void onConnectionClosed(String srcIp, int srcPort, String dstIp, int dstPort, boolean overTcp) {
        tracker.remove(ConnectionKey.of(srcIp, srcPort, dstIp, dstPort, overTcp));
    }
}
