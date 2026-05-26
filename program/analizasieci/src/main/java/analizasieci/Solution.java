package analizasieci;

import analizasieci.packetCapture.DeviceManager;
import analizasieci.packetCapture.PacketCaptureService;
import analizasieci.packetCapture.PacketLookupRow;
import analizasieci.windowsControls.WindowManager;
import org.pcap4j.core.PcapNetworkInterface;

import java.awt.*;
import java.util.List;
import java.util.function.Consumer;

public class Solution {
    DeviceManager deviceManager;
    PacketCaptureService packetCapture;
    public Solution(){
        deviceManager = new DeviceManager();
        packetCapture = new PacketCaptureService();
    }
    public List<PcapNetworkInterface> getDevices(){
        return deviceManager.getDevices();
    }
    public void getInterfacesInfo(){
        deviceManager.getInterfacesInfo();
    }
    public void selectNetworkInterface(int n){
        packetCapture.setHandle(deviceManager.selectNetworkInterface(n));
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
