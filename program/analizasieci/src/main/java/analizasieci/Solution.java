package analizasieci;

import analizasieci.packetCapture.PacketCaptureService;
import analizasieci.packetCapture.PacketLookupRow;
import analizasieci.windowsControls.WindowManager;
import org.pcap4j.core.PcapNetworkInterface;

import java.awt.*;
import java.util.List;
import java.util.function.Consumer;

public class Solution {
    PacketCaptureService packetCapture = new PacketCaptureService();
    public void launch(){
        packetCapture.init(4);

    }
    public List<PcapNetworkInterface> getDevices(){
        return packetCapture.getDevices();
    }
    public void getInterfacesInfo(){
        packetCapture.getInterfacesInfo();
    }
    public void selectNetworkInterface(int n){
        packetCapture.selectNetworkInterface(n);
    }
    public void listeningLoop(Consumer<PacketLookupRow> uiUpdater){
        Thread captureThread = new Thread(() -> {
            packetCapture.listeningLoop(uiUpdater);
        });

        captureThread.setDaemon(true);

        captureThread.start();
    }
    public void stopListening(){
        packetCapture.stopListening();
    }
}
