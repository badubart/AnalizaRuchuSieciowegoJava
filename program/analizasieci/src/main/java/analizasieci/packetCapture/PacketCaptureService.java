package analizasieci.packetCapture;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.function.Consumer;
import java.net.Inet4Address;
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

    PacketFileWriter fileWriter;

    public PacketCaptureService() {
        isListening = false;
    }

    public void setHandle(PcapHandle handle) {
        this.handle = handle;
    }


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
    public Path getPath(){
        return Paths.get(System.getProperty("user.dir"), "temp_capture.pcap");
    }
    public PacketFileWriter getFileWriter(){return fileWriter;}
    public int getTotalSent(){return totalSent;}
    public int getTotalReceived(){return totalReceived;}
    public int getCountSent(){return countSent;}
    public int getCountReceived(){return countReceived;}
}