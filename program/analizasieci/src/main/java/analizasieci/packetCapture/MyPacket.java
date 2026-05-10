package analizasieci.packetCapture;

import org.pcap4j.packet.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;


public class MyPacket
{
    private final int length;
    private final String timeStamp;

    String source;
    String destination;
    String protocol;
    private final List<ProtocolLayer> layers = new ArrayList<>();

    boolean isSuspicoius;

    public String getProtocol()
    {
        return protocol;
    }
    public String getSourceIP()
    {
        return sourceIp;
    }
    public String getDestinationIP()
    {
        return destinationIp;
    }
    public String getTime()
    {
        return timeStamp;
    }
    public int getPort()
    {
        return port;
    }
    public MyPacket(String newProtocol, int newPort, String newSourceIP, String newDestinationIP, String newTimeStamp)
    {
        protocol = newProtocol;
        port = newPort;
        sourceIp = newSourceIP;
        destinationIp = newDestinationIP;
        timeStamp = newTimeStamp;
    }

    public void wypisz()
    {
        System.out.println("Protokół: "+ protocol);
        System.out.println("Port: "+port);
        System.out.println("Adres nadawcy: "+sourceIp);
        System.out.println("Adres docelowy: "+destinationIp);
        System.out.println("Czas: "+timeStamp);
    }
}