package analizasieci.packetAnomalies.anomalies;

import analizasieci.packetAnomalies.AnomalyDetector;
import analizasieci.packetAnomalies.TcpTransmission;
import analizasieci.packetCapture.MyPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.util.HashMap;
import java.util.Map;

public class RetransmissionAnomaly implements AnomalyDetector {

    final private Map<TcpTransmission, Long> currentSessions = new HashMap<>();



    @Override public String inspect(MyPacket packet, Packet raw, long nowMs)
    {
        String Wynik = null;
        TcpPacket tcp = raw.get(TcpPacket.class);
        IpV4Packet ip = raw.get(IpV4Packet.class);

        if(tcp == null || ip == null)
        {
            return null;
        }

        TcpTransmission session = new TcpTransmission(
                ip.getHeader().getSrcAddr().getHostAddress(),
                tcp.getHeader().getSrcPort().valueAsInt(),
                ip.getHeader().getDstAddr().getHostAddress(),
                tcp.getHeader().getDstPort().valueAsInt()
        );

        long seq = tcp.getHeader().getSequenceNumberAsLong();

        int payloadLen;

        if(tcp.getPayload()==null)
        {
            payloadLen = 0;
        }
        else
        {
            payloadLen = tcp.getPayload().length();
        }

        Long highest = currentSessions.get(session);
        long endSeq = seq + payloadLen;

        if(payloadLen == 0)
        {
            return null;
        }

        if(highest != null && endSeq <= highest)
        {
            Wynik =  "Retransmisja pakietu";
        }

        currentSessions.put(
                session,
                Math.max(
                        highest == null ? 0 : highest,
                        endSeq
                )
        );
        if(tcp.getHeader().getFin() || tcp.getHeader().getRst())
        {
            currentSessions.remove(session);
        }

        return Wynik;
    }

    @Override public String getName()
    {
        return "Retransmission";
    }



}
