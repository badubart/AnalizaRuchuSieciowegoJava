package analizasieci.packetCapture;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.function.Consumer;

import analizasieci.network.NetworkUtils;
import analizasieci.packetAnalysis.PacketAnalyzer;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

/**
 * Usługa przechwytywania pakietów z wybranego interfejsu.
 * <p>
 * W pętli nasłuchu odbiera pakiety z uchwytu pcap, zapisuje je do tymczasowego pliku
 * pcap ({@link PacketFileWriter}), analizuje ({@link PacketAnalyzer}) i przekazuje
 * lekki wiersz {@link PacketLookupRow} do UI. Prowadzi też statystyki wysłanych/
 * odebranych pakietów i bajtów (na podstawie lokalnego adresu IP).
 */
public class PacketCaptureService {
    volatile boolean isListening;
    PcapHandle handle;

    private int totalSent = 0;
    private int totalReceived = 0;
    private int countSent = 0;
    private int countReceived = 0;
    private final String localAddress = NetworkUtils.getLocalIpv4Address();

    PacketFileWriter fileWriter;

    public PacketCaptureService() {
        isListening = false;
    }

    /** Ustawia uchwyt pcap (otwarty na wybranym interfejsie), na którym odbywa się nasłuch. */
    public void setHandle(PcapHandle handle) {
        this.handle = handle;
    }


    /**
     * Główna pętla nasłuchu: odbiera, zapisuje i analizuje pakiety aż do
     * {@link #stopListening()}. Powinna być uruchamiana na osobnym wątku.
     *
     * @param uiUpdater callback wywoływany dla każdego przechwyconego pakietu (może być {@code null})
     */
    public void listeningLoop(Consumer<PacketLookupRow> uiUpdater) {
        int i = 0;
        Packet packet;

        try {
            fileWriter = new PacketFileWriter(handle, Paths.get(System.getProperty("user.dir"), "temp_capture.pcap"));
            isListening = true;

            while (isListening) {
                packet = handle.getNextPacket();
                if (packet == null) {
                    continue;
                }
                long offset = fileWriter.writePacket(packet);

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

                PacketLookupRow newPacket = new PacketLookupRow(
                        i,
                        offset,
                        analyzedPacket.getSourceIp(),
                        analyzedPacket.getDestinationIp(),
                        analyzedPacket.getHighestProtocolName(),
                        analyzedPacket.getPacketLength(),
                        analyzedPacket.getTimeStamp(),
                        analyzedPacket.getInfo(),
                        analyzedPacket.getSourceMAC(),
                        analyzedPacket.getDestinationMAC(),
                        analyzedPacket.isAnomaly()
                );


                if (uiUpdater != null) {
                    uiUpdater.accept(newPacket);
                }
                i++;
            }
        } catch (NotOpenException e) {
            System.out.println("Nastąpił wyjątek NotOpenException!");
        } catch (PcapNativeException e) {
            System.out.println("Nie udało się otworzyć pliku pcap do zapisu: " + e.getMessage());
        } catch (IOException e){
            e.printStackTrace();
        } finally {
            if (fileWriter != null) {
                fileWriter.close();
            }
        }
    }

    /** Sygnalizuje zatrzymanie pętli nasłuchu i zamyka uchwyt pcap. */
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
    /** @return ścieżka tymczasowego pliku pcap z bieżącą sesją przechwytywania. */
    public Path getPath(){
        return Paths.get(System.getProperty("user.dir"), "temp_capture.pcap");
    }
    /** @return obiekt zapisujący pakiety do pliku (lub {@code null}, gdy nasłuch nie wystartował). */
    public PacketFileWriter getFileWriter(){return fileWriter;}
    /** @return łączny wolumen wysłanych danych w bajtach. */
    public int getTotalSent(){return totalSent;}
    /** @return łączny wolumen odebranych danych w bajtach. */
    public int getTotalReceived(){return totalReceived;}
    /** @return liczba wysłanych pakietów. */
    public int getCountSent(){return countSent;}
    /** @return liczba odebranych pakietów. */
    public int getCountReceived(){return countReceived;}
}