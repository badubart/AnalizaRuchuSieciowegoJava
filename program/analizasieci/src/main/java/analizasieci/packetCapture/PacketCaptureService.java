package analizasieci.packetCapture;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
public class PacketCaptureService {
    volatile boolean isListening;
    List<PcapNetworkInterface> devices;
    PcapHandle handle;
    List<Packet> pakiety;

    {
        try{
            isListening = false;
            devices = Pcaps.findAllDevs();
            pakiety = new ArrayList<>();
        } catch(PcapNativeException e){
            System.out.println("Nie znaleziono pakietu Pcap4j!");
        }
    }

    public void listeningLoop(Consumer<PacketLookupRow> uiUpdater){
        int i=0;
        Packet packet;
        try {
            isListening = true;
            while (isListening) {
                packet = handle.getNextPacket();
                if (packet == null) {
                    continue;
                }
                pakiety.add(packet);

                String src = "Brak";
                String dst = "Brak";
                String proto = "Inny";
                String info = "";

                if (packet.contains(IpV4Packet.class)) {
                    IpV4Packet ip = packet.get(IpV4Packet.class);
                    src = ip.getHeader().getSrcAddr().getHostAddress();
                    dst = ip.getHeader().getDstAddr().getHostAddress();
                    proto = ip.getHeader().getProtocol().name();
                }
                else if (packet.contains(IpV6Packet.class)) {
                    IpV6Packet ipv6 = packet.get(IpV6Packet.class);
                    src = ipv6.getHeader().getSrcAddr().getHostAddress();
                    dst = ipv6.getHeader().getDstAddr().getHostAddress();
                    proto = "IPv6";
                }
                else if (packet.contains(ArpPacket.class)) {
                    ArpPacket arp = packet.get(ArpPacket.class);
                    src = arp.getHeader().getSrcHardwareAddr().toString();
                    dst = "Broadcast";
                    proto = "ARP";
                    info = "Zapytanie o IP: " + arp.getHeader().getDstProtocolAddr();
                }

                if (packet.contains(TcpPacket.class)) {
                    TcpPacket tcp = packet.get(TcpPacket.class);
                    info = "Port: " + tcp.getHeader().getSrcPort().valueAsInt() + " -> " + tcp.getHeader().getDstPort().valueAsInt();
                } else if (packet.contains(UdpPacket.class)) {
                    UdpPacket udp = packet.get(UdpPacket.class);
                    info = "Port: " + udp.getHeader().getSrcPort().valueAsInt() + " -> " + udp.getHeader().getDstPort().valueAsInt();
                }

                PacketLookupRow newPacket = new PacketLookupRow(i, src, dst, proto, packet.length(), info);

                if (uiUpdater != null) {
                    uiUpdater.accept(newPacket);
                }

//                System.out.println("Pakiet " + i + " ----------------------------");
//
//                if (packet.contains(IpV4Packet.class)) {
//                    IpV4Packet ip = packet.get(IpV4Packet.class);
//                    System.out.println("Typ: IPv4");
//                    System.out.println("Adres IP nadawcy: " + ip.getHeader().getSrcAddr().getHostAddress());
//                    System.out.println("Adres IP odbiorcy: " + ip.getHeader().getDstAddr().getHostAddress());
//                    System.out.println("Protokół: " + ip.getHeader().getProtocol());
//                }
//                else if (packet.contains(IpV6Packet.class)) {
//                    IpV6Packet ipv6 = packet.get(IpV6Packet.class);
//                    System.out.println("Typ: IPv6");
//                    System.out.println("Adres IPv6 nadawcy: " + ipv6.getHeader().getSrcAddr().getHostAddress());
//                    System.out.println("Adres IPv6 odbiorcy: " + ipv6.getHeader().getDstAddr().getHostAddress());
//                }
//                else if (packet.contains(ArpPacket.class)) {
//                    ArpPacket arp = packet.get(ArpPacket.class);
//                    System.out.println("Typ: ARP (" + arp.getHeader().getOperation().name() + ")");
//                    System.out.println("MAC nadawcy: " + arp.getHeader().getSrcHardwareAddr());
//                    System.out.println("IP nadawcy: " + arp.getHeader().getSrcProtocolAddr());
//                    System.out.println("Pytano o IP: " + arp.getHeader().getDstProtocolAddr());
//                }
//                else {
//                    System.out.println("Typ: Inny pakiet (np. warstwa łącza danych bez IP)");
//                    System.out.println("Długość: " + packet.length() + " bajtów");
//                }
//
//                if (packet.contains(TcpPacket.class)) {
//                    TcpPacket tcp = packet.get(TcpPacket.class);
//                    System.out.println("Port źródłowy (TCP): " + tcp.getHeader().getSrcPort().valueAsInt());
//                    System.out.println("Port docelowy (TCP): " + tcp.getHeader().getDstPort().valueAsInt());
//                } else if (packet.contains(UdpPacket.class)) {
//                    UdpPacket udp = packet.get(UdpPacket.class);
//                    System.out.println("Port źródłowy (UDP): " + udp.getHeader().getSrcPort().valueAsInt());
//                    System.out.println("Port docelowy (UDP): " + udp.getHeader().getDstPort().valueAsInt());
//                }
//                System.out.println("Koniec pakietu " + i + " --------------------");

                i++;

            }
        } catch(NotOpenException e){
            System.out.println("nastąpił wyjątek NotOpenException!");
        }
    }
    public void loadDevices(){
        try {
            devices = Pcaps.findAllDevs();
        }catch(PcapNativeException e){
            System.out.println("Nie znaleziono pakietu Pcap4j!");
        }
    }
    public List<PcapNetworkInterface> getDevices(){
        return devices;
    }
    public void stopListening(){
        isListening = false;

        if (handle != null && handle.isOpen()) {
            try {
                handle.breakLoop();
            } catch (NotOpenException e) {
                System.out.println("Uchwyt pcap był już zamknięty podczas próby przerwania pętli.");
            } finally {
                handle.close();
            }
        }
    }
    public void selectNetworkInterface(int n){
        try {
            handle = devices.get(n).openLive(65536, PromiscuousMode.PROMISCUOUS, 10);
        } catch(IndexOutOfBoundsException e){
            System.out.println("Podano nieistniejący interfejs!");
        } catch(PcapNativeException e) {
            System.out.println("Nie znaleziono pakietu Pcap4j!");
        }
    }
    public void getInterfacesInfo(){
        for (int i = 0; i < devices.size(); i++) {
            System.out.println(i + " -> " + devices.get(i).getDescription());
        }
    }
    public void init(int n){
        this.loadDevices();
        this.getInterfacesInfo();
        this.selectNetworkInterface(n);
        this.stopListening();
    }
}
