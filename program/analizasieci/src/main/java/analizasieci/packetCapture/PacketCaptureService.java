package analizasieci.packetCapture;

import java.net.Inet4Address;
import java.nio.file.Paths;
import java.util.function.Consumer;

import analizasieci.network.NetworkUtils;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

public class PacketCaptureService {
    volatile boolean isListening;
    PcapHandle handle;

    private int totalSent = 0;
    private int totalReceived = 0;
    private int countSent = 0;
    private int countReceived = 0;
    private final String localAddress = NetworkUtils.getLocalIpv4Address();

    // Dodajemy referencję do writera
    PacketFileWriter fileWriter;

    public PacketCaptureService() {
        isListening = false;
        // Usunięto: pakiety = new ArrayList<>();
    }



    public void setHandle(PcapHandle handle) {
        this.handle = handle;
    }

    // Zmieniono sygnaturę: dodano pcapFilePath, w którym zapiszemy zrzut
    public void listeningLoop(Consumer<PacketLookupRow> uiUpdater) {
        String pcapFilePath = "capture.pcap";
        int i = 0;
        Packet packet;

        try {
            // Inicjalizacja zapisywania do pliku
            fileWriter = new PacketFileWriter(handle, pcapFilePath);
            isListening = true;

            while (isListening) {
                packet = handle.getNextPacket();
                if (packet == null) {
                    continue;
                }

                // 1. Zapisz oryginalny pakiet do pliku i pobierz offset
                long offset = fileWriter.writePacket(packet);

                // 2. Szybka analiza tylko w celu wyciągnięcia metadanych dla UI
                MyPacket analyzedPacket = PacketAnalyzer.analyze(packet);

                if (localAddress.equals(analyzedPacket.getSourceIp()))
                {
                    totalSent+=analyzedPacket.getPacketLength();
                    countSent+=1;
                }
                else
                {
                    totalReceived+=analyzedPacket.getPacketLength();
                    countReceived+=1;
                }


                // 3. Stwórz lekki wiersz z offsetem i danymi podglądowymi (bez obiektu MyPacket)
                PacketLookupRow newPacket = new PacketLookupRow(
                        i,
                        offset,
                        analyzedPacket.getSourceIp(),
                        analyzedPacket.getDestinationIp(),
                        analyzedPacket.getHighestProtocolName(),
                        analyzedPacket.getPacketLength(),
                        analyzedPacket.getTimeStamp(),
                        analyzedPacket.getInfo(),
                        analyzedPacket.getSourceMAC(),      // <-- Dodane
                        analyzedPacket.getDestinationMAC(), // <-- Dodane
                        analyzedPacket.isAnomaly()          // <-- Dodane
                );

                // MyPacket nie jest nigdzie zapisywany, więc po wyjściu z tej iteracji
                // pętli zostanie automatycznie usunięty przez Garbage Collector.

                if (uiUpdater != null) {
                    uiUpdater.accept(newPacket);
                }
                i++;
            }
        } catch (NotOpenException e) {
            System.out.println("Nastąpił wyjątek NotOpenException!");
        } catch (PcapNativeException e) {
            System.out.println("Nie udało się otworzyć pliku pcap do zapisu: " + e.getMessage());
        } finally {
            // Bezpieczne zamknięcie pliku po wyjściu z pętli
            if (fileWriter != null) {
                fileWriter.close();
            }
        }
    }

    public void stopListening() {
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

    public int getTotalSent(){return totalSent;}
    public int getTotalReceived(){return totalReceived;}
    public int getCountSent(){return countSent;}
    public int getCountReceived(){return countReceived;}
}
