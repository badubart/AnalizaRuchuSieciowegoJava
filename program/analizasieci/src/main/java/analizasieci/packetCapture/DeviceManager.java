package analizasieci.packetCapture;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.util.List;

public class DeviceManager {
    List<PcapNetworkInterface> devices;
    public DeviceManager(){
        loadDevices();
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
    public PcapHandle selectNetworkInterface(int n){
        try {
            return devices.get(n).openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
        } catch(IndexOutOfBoundsException e){
            System.out.println("Podano nieistniejący interfejs!");
        } catch(PcapNativeException e) {
            System.out.println("Nie znaleziono pakietu Pcap4j!");
        }
        return null;
    }
    public void getInterfacesInfo(){
        for (int i = 0; i < devices.size(); i++) {
            System.out.println(i + " -> " + devices.get(i).getDescription());
        }
    }
}
