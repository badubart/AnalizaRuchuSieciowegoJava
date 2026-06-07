package analizasieci.packetCapture.packetLayers;

import analizasieci.packetCapture.ConnectionKey;
import analizasieci.packetCapture.ConnectionTracker;
import analizasieci.packetCapture.MyPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import analizasieci.packetCapture.packetLayers.protocolMatchers.*;

import java.nio.charset.StandardCharsets;
import java.util.Comparator;
import java.util.List;

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
            myPacket.setHighestProtocolName(r.matcher().getName());
            myPacket.addLayer(r.layer());
        } else {
            myPacket.setHighestProtocolName("Data");
            myPacket.addLayer(new RawData(payload));
        }
    }
    public static void evictIdleConnections(long idleMs) { tracker.evictIdle(idleMs); }
}
