package analizasieci.packetAnomalies;

import org.pcap4j.packet.namednumber.TcpPort;

import java.net.Inet4Address;

/**
 * Identyfikator transmisji TCP (czwórka: adres i port źródłowy oraz docelowy).
 * <p>
 * Definiuje {@code equals}/{@code hashCode}, dzięki czemu może służyć jako klucz
 * w mapach grupujących pakiety należące do tego samego przepływu TCP.
 */
public class TcpTransmission {
    private String srcAddres;
    private int srcPort;
    private String dstAddress;
    private int dstPort;

    /**
     * @param srcAddres  adres źródłowy
     * @param srcPort    port źródłowy
     * @param dstAddress adres docelowy
     * @param dstPort    port docelowy
     */
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
