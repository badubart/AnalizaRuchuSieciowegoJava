package analizasieci.packetCapture;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;

import java.io.Closeable;
import java.io.IOException;
import java.io.RandomAccessFile;

public class PacketFileReader implements Closeable {
    private final RandomAccessFile file;
    private final boolean littleEndian;

    public PacketFileReader(String path) throws IOException {
        file = new RandomAccessFile(path, "r");
        int magic = file.readInt();
        littleEndian = (magic == 0xd4c3b2a1); // - ustawia endianizm (nie wiem skad ta liczba, ale działa - i jest w dokumentacji)
    }

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