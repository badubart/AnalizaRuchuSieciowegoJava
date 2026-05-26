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
    PcapHandle handle;
    List<Packet> pakiety;

    public PacketCaptureService(){
        isListening = false;
        pakiety = new ArrayList<>();
    }
    public void setHandle(PcapHandle handle){
        this.handle = handle;
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
                MyPacket analyzedPacket = PacketAnalyzer.analyze(packet);
                pakiety.add(packet);
                PacketLookupRow newPacket = new PacketLookupRow(i, analyzedPacket);
                if (uiUpdater != null) {
                    uiUpdater.accept(newPacket);
                }
                i++;
            }
        } catch(NotOpenException e){
            System.out.println("nastąpił wyjątek NotOpenException!");
        }
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


//    public void loadDevices(){
//        try {
//            devices = Pcaps.findAllDevs();
//        }catch(PcapNativeException e){
//            System.out.println("Nie znaleziono pakietu Pcap4j!");
//        }
//    }
//    public List<PcapNetworkInterface> getDevices(){
//        return devices;
//    }
//    public void selectNetworkInterface(int n){
//        try {
//            handle = devices.get(n).openLive(65536, PromiscuousMode.PROMISCUOUS, 10);
//        } catch(IndexOutOfBoundsException e){
//            System.out.println("Podano nieistniejący interfejs!");
//        } catch(PcapNativeException e) {
//            System.out.println("Nie znaleziono pakietu Pcap4j!");
//        }
//    }
}
