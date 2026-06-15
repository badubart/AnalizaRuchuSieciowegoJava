package analizasieci.packetAnomalies.anomalies;

import analizasieci.packetAnomalies.AnomalyDetector;
import analizasieci.packetCapture.MyPacket;
import org.pcap4j.packet.Packet;

import java.net.InetAddress;

/**
 * Kontekst weryfikacji sumy kontrolnej – przechowuje adresy IP potrzebne do
 * zbudowania pseudo-nagłówka przy liczeniu sum TCP/UDP.
 */
public class ChecksumContext implements AnomalyDetector {
    /** Adres źródłowy (do pseudo-nagłówka). */
    public InetAddress srcIp;
    /** Adres docelowy (do pseudo-nagłówka). */
    public InetAddress dstIp;

    @Override
    public String getName() { return "Checksum"; }
    @Override
    public String inspect(MyPacket packet, Packet raw, long nowMs) { return "Temp"; }
}
