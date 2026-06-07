package analizasieci.packetAnomalies;

import org.pcap4j.packet.namednumber.TcpPort;

import java.net.Inet4Address;

public class TcpTransmission {
    private String srcAddres;
    private int srcPort;
    private String dstAddress;
    private int dstPort;

    public TcpTransmission(String srcAddres, int srcPort, String dstAddress, int dstPort)
    {
        this.srcAddres=srcAddres;
        this.srcPort=srcPort;
        this.dstAddress=dstAddress;
        this.dstPort=dstPort;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TcpTransmission)) return false;

        TcpTransmission that = (TcpTransmission) o;

        return srcPort == that.srcPort
                && dstPort == that.dstPort
                && srcAddres.equals(that.srcAddres)
                && dstAddress.equals(that.dstAddress);
    }

    @Override
    public int hashCode() {
        int result = srcAddres.hashCode();
        result = 31 * result + srcPort;
        result = 31 * result + dstAddress.hashCode();
        result = 31 * result + dstPort;
        return result;
    }

}
