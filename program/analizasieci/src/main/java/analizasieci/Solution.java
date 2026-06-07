package analizasieci;

import analizasieci.packetCapture.DeviceManager;
import analizasieci.packetCapture.PacketCaptureService;
import analizasieci.packetCapture.PacketAnalyzer;
import analizasieci.packetCapture.PacketLookupRow;
import analizasieci.report.HtmlReportGenerator;
import analizasieci.windowsControls.WindowManager;
import org.pcap4j.core.PcapNetworkInterface;

import java.io.IOException;
import java.nio.file.Path;
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
    public String getPcapFilePath(){
        return "capture.pcap";
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

    public void generateHtmlReport(Path outputFile) throws IOException {
        HtmlReportGenerator.writeReport(
                outputFile,
                PacketAnalyzer.getAnomalyCount(),
                packetCapture.getTotalSent(),
                packetCapture.getTotalReceived(),
                packetCapture.getCountSent(),
                packetCapture.getCountReceived()
        );
    }
}
