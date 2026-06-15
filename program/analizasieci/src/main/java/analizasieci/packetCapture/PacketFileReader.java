package analizasieci.packetCapture;
import analizasieci.packetAnalysis.PacketAnalyzer;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;

import java.io.Closeable;
import java.io.IOException;
import java.io.RandomAccessFile;

/**
 * Odczyt pojedynczych pakietów z pliku w formacie pcap z dostępem swobodnym.
 * <p>
 * Pozwala na "leniwe" wczytanie pełnej zawartości pakietu dopiero w momencie
 * zaznaczenia wiersza w UI – na podstawie zapamiętanego offsetu w pliku.
 * Na podstawie magic number nagłówka globalnego rozpoznaje kolejność bajtów
 * (little/big endian). Implementuje {@link Closeable}.
 */
public class PacketFileReader implements Closeable {
    private final RandomAccessFile file;
    private final boolean littleEndian;

    /**
     * Otwiera plik pcap do odczytu i ustala kolejność bajtów na podstawie magic number.
     *
     * @param path ścieżka do pliku .pcap
     * @throws IOException gdy pliku nie da się otworzyć lub odczytać nagłówka
     */
    public PacketFileReader(String path) throws IOException {
        file = new RandomAccessFile(path, "r");
        int magic = file.readInt();
        littleEndian = (magic == 0xd4c3b2a1); // - ustawia endianizm (nie wiem skad ta liczba, ale działa - i jest w dokumentacji)
    }

    /**
     * Czyta i analizuje pakiet zapisany pod wskazanym offsetem w pliku pcap.
     *
     * @param offset pozycja nagłówka rekordu pakietu w pliku (z {@code PacketFileWriter})
     * @return przeanalizowany pakiet {@link MyPacket} wraz z warstwami i znacznikiem czasu
     * @throws IOException przy błędzie odczytu pliku
     * @throws IllegalRawDataException gdy bajty nie tworzą poprawnej ramki Ethernet
     */
    public MyPacket readPacket(long offset) throws IOException, IllegalRawDataException {
        file.seek(offset);
        long tsSec  = readInt() & 0xFFFFFFFFL;
        long tsUsec = readInt() & 0xFFFFFFFFL;
        long tsMs   = tsSec * 1000 + tsUsec / 1000;
        file.seek(offset + 8);
        int inclLen = readInt();
        file.seek(offset + 16);
        byte[] data = new byte[inclLen];
        file.readFully(data);

        Packet packet = EthernetPacket.newPacket(data, 0, data.length);
        return PacketAnalyzer.analyze(packet, tsMs);
    }

    private int readInt() throws IOException {
        int val = file.readInt();
        return littleEndian ? Integer.reverseBytes(val) : val;
    }
    @Override
    public void close() throws IOException { file.close(); }
}