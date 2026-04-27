package analizasieci;

import java.util.ArrayList;
import java.util.List;

import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

public class PacketCaptureService {
    public static void main(String[] args) throws Exception {
        List<PcapNetworkInterface> devices = Pcaps.findAllDevs();
        
        // Pobranie listy interfejsów
        for (int i = 0; i < devices.size(); i++) 
        {
            System.out.println(i + " -> " + devices.get(i).getDescription());
        }

        PcapNetworkInterface devRealtek = devices.get(4); 

        PcapHandle handle = devRealtek.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);
        
        Packet packet;
        List<Packet> pakiety = new ArrayList<>();
        int i=0;

        while (i<100)
        {
            packet = handle.getNextPacket();
            pakiety.add(packet);
            if (packet == null) {
                continue;
            }
            if(packet.contains(IpV4Packet.class))
            {
                System.out.println("Pakiet "+i+" ----------------------------");
                IpV4Packet ip = packet.get(IpV4Packet.class);
                System.out.println("Adres IP nadawcy: "+ip.getHeader().getSrcAddr().getHostAddress());
                System.out.println("Adres IP odbiorcy: "+ ip.getHeader().getDstAddr().getHostAddress());
                System.out.println("Protokół: "+ip.getHeader().getProtocol());
            }
            if(packet.contains(TcpPacket.class))
            {
                TcpPacket tcp = packet.get(TcpPacket.class);
                System.out.println("Port: "+tcp.getHeader().getDstPort());
            }
            System.out.println("Koniec pakietu "+i+" --------------------");
            i++;
        }


    }
}
