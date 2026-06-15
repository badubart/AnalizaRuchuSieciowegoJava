package analizasieci.packetCapture;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.util.List;

/**
 * Zarządza interfejsami sieciowymi widocznymi dla biblioteki pcap4j.
 * Ładuje listę urządzeń przy utworzeniu i pozwala otworzyć uchwyt
 * przechwytywania na wybranym interfejsie.
 */
public class DeviceManager {
    List<PcapNetworkInterface> devices;
    /** Tworzy menedżera i od razu ładuje listę dostępnych interfejsów. */
    public DeviceManager(){
        loadDevices();
    }
    /** Ładuje (lub odświeża) listę interfejsów sieciowych z pcap4j. */
    public void loadDevices(){
        try {
            devices = Pcaps.findAllDevs();
        }catch(PcapNativeException e){
            System.out.println("Nie znaleziono pakietu Pcap4j!");
        }
    }
    /** @return lista dostępnych interfejsów sieciowych. */
    public List<PcapNetworkInterface> getDevices(){
        return devices;
    }
    /**
     * Otwiera uchwyt przechwytywania (tryb promiscuous) na wybranym interfejsie.
     *
     * @param n indeks interfejsu na liście {@link #getDevices()}
     * @return otwarty {@link PcapHandle} lub {@code null}, gdy indeks jest błędny lub wystąpił błąd
     */
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
    /** Wypisuje na konsolę numerowaną listę interfejsów (diagnostyka). */
    @Deprecated
    public void getInterfacesInfo(){
        for (int i = 0; i < devices.size(); i++) {
            System.out.println(i + " -> " + devices.get(i).getDescription());
        }
    }
}
