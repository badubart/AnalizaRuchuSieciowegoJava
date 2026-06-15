package analizasieci;

import analizasieci.packetAnalysis.PacketAnalyzer;
import analizasieci.packetCapture.*;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import analizasieci.report.HtmlReportGenerator;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.function.Consumer;

/**
 * Fasada logiki aplikacji – spina warstwy między interfejsem (kontrolerami JavaFX)
 * a mechanizmami przechwytywania, analizy i zapisu pakietów.
 * <p>
 * Udostępnia operacje wysokiego poziomu: pobranie i wybór interfejsu sieciowego,
 * start/stop nasłuchiwania (na osobnym wątku), zapis przechwyconych pakietów do
 * pliku, usuwanie pliku tymczasowego oraz generowanie raportu HTML.
 */
public class Solution {
    DeviceManager deviceManager;
    PacketCaptureService packetCapture;
    PacketFileWriter packetFileWriter;
    private Thread captureThread;
    public Solution(){
        deviceManager = new DeviceManager();
        packetCapture = new PacketCaptureService();

    }
    /** @return lista dostępnych interfejsów sieciowych. */
    public List<PcapNetworkInterface> getDevices(){
        return deviceManager.getDevices();
    }
    /** Wypisuje informacje o interfejsach sieciowych (diagnostyka konsolowa). */
    public void getInterfacesInfo(){
        deviceManager.getInterfacesInfo();
    }
    /**
     * Wybiera interfejs do nasłuchu i otwiera na nim uchwyt przechwytywania.
     *
     * @param n indeks interfejsu na liście z {@link #getDevices()}
     */
    public void selectNetworkInterface(int n){
        packetCapture.setHandle(deviceManager.selectNetworkInterface(n));
    }
    /** @return ścieżka tymczasowego pliku pcap, do którego trafiają przechwytywane pakiety. */
    public Path getPcapFilePath(){
        return packetCapture.getPath();
    }
    /**
     * Startuje nasłuchiwanie pakietów na osobnym wątku (demonie).
     *
     * @param uiUpdater callback wywoływany dla każdego nowego pakietu (aktualizacja UI)
     */
    public void listeningLoop(Consumer<PacketLookupRow> uiUpdater){
        captureThread = new Thread(() -> {
            packetCapture.listeningLoop(uiUpdater);
        });

        captureThread.setDaemon(true);

        captureThread.start();
    }
    /**
     * Zatrzymuje nasłuchiwanie i czeka na zakończenie wątku przechwytywania
     * (aby plik tymczasowy został domknięty przed ewentualnym usunięciem/zapisem).
     */
    public void stopListening(){
        packetCapture.stopListening();
        if (captureThread != null) {
            try {
                captureThread.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            captureThread = null;
        }
    }

    public void deleteTempCaptureFile(){
        try {
            Files.deleteIfExists(getPcapFilePath());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public void saveCaptureAs(Path dstPath) throws IOException {
        PacketFileWriter file = packetCapture.getFileWriter();
        if (file != null) {
            try {
                file.flush();
            } catch (NotOpenException | PcapNativeException e) {
                e.printStackTrace();
            }
        }

        Path srcPath = getPcapFilePath();
        if (dstPath.getParent() != null) {
            Files.createDirectories(dstPath.getParent());
        }
        Files.copy(srcPath, dstPath, StandardCopyOption.REPLACE_EXISTING);
    }

    public boolean hasCapturedPackets() {
        PacketFileWriter file = packetCapture.getFileWriter();
        return file != null && file.size() > 24;
    }
    /**
     * Generuje raport HTML ze statystykami ruchu i wykrytymi anomaliami.
     *
     * @param outputFile docelowy plik raportu
     * @throws IOException przy błędzie zapisu
     */
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
