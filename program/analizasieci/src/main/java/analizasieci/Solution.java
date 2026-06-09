package analizasieci;

import analizasieci.packetCapture.*;
import analizasieci.windowsControls.WindowManager;
import org.pcap4j.core.PcapNetworkInterface;
import analizasieci.report.HtmlReportGenerator;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.function.Consumer;

public class Solution {
    DeviceManager deviceManager;
    PacketCaptureService packetCapture;
    PacketFileWriter packetFileWriter;
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
    public Path getPcapFilePath(){
        return packetCapture.getPath();
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

    public void closeAndSave(){
        PacketFileWriter file = packetCapture.getFileWriter();
        file.close();
        Path srcPath = getPcapFilePath();
        Path dstPath = Paths.get(System.getProperty("user.dir"), "saved_files", LocalTime.now().format(DateTimeFormatter.ofPattern("HHmmss"))+"_saved_packets.pcap");

        try {
            if (dstPath.getParent() != null) {
                Files.createDirectories(dstPath.getParent());
            }

            Files.move(srcPath, dstPath, StandardCopyOption.REPLACE_EXISTING);
        } catch(IOException e){
            e.printStackTrace();
        }
        System.exit(0);
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
