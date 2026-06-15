package analizasieci.packetCapture;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.Packet;

import java.io.Closeable;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

/**
 * Zapis przechwyconych pakietów do pliku w formacie pcap.
 * <p>
 * Opakowuje {@link PcapDumper} z pcap4j i śledzi bieżący offset w pliku, dzięki czemu
 * każdy zapisany pakiet zwraca swoją pozycję – wykorzystywaną później przez
 * {@link PacketFileReader} do "leniwego" odczytu. Implementuje {@link Closeable}.
 * Offset startowy 24 odpowiada wielkości nagłówka globalnego pliku pcap.
 */
public class PacketFileWriter implements Closeable {
    private final PcapDumper dumper;
    private long currentOffset = 24;
    private Path path;

    /**
     * Otwiera plik pcap do zapisu (tworząc brakujące katalogi nadrzędne).
     *
     * @param handle otwarty uchwyt pcap, z którego pochodzą pakiety
     * @param path   docelowa ścieżka pliku .pcap
     * @throws PcapNativeException błąd biblioteki natywnej pcap
     * @throws NotOpenException    gdy uchwyt nie jest otwarty
     * @throws IOException         błąd tworzenia katalogów
     */
    public PacketFileWriter(PcapHandle handle, Path path) throws PcapNativeException, NotOpenException, IOException {
        this.path = path.toAbsolutePath();

        Path parentDir = this.path.getParent();
        if (parentDir != null && !Files.exists(parentDir)) {
            Files.createDirectories(parentDir); // Tworzy wszystkie brakujące foldery po drodze
        }

        this.dumper = handle.dumpOpen(this.path.toString());
    }
    /** @return ścieżka pliku, do którego zapisywane są pakiety. */
    public Path getPath(){
        return path;
    }
    /**
     * Zapisuje pakiet i przesuwa offset (16 B nagłówka rekordu + długość danych).
     *
     * @param packet pakiet do zapisania
     * @return offset, pod którym zapisano rekord (do późniejszego odczytu)
     * @throws NotOpenException gdy plik/uchwyt jest już zamknięty
     */
    public long writePacket(Packet packet) throws NotOpenException {
        long offset = currentOffset;
        dumper.dump(packet);
        currentOffset += 16 + packet.getRawData().length;
        return offset;
    }
    /** @return bieżący rozmiar pliku w bajtach (offset za ostatnim rekordem). */
    public long size() { return currentOffset; }

    /** Wymusza zrzut buforów na dysk. */
    public void flush() throws NotOpenException, PcapNativeException { dumper.flush(); }

    /** Zamyka plik (dumper). */
    @Override
    public void close() { dumper.close(); }
}
