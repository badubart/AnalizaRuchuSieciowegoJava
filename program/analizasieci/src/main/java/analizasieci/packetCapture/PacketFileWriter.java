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

public class PacketFileWriter implements Closeable {
    private final PcapDumper dumper;
    private long currentOffset = 24;
    private Path path;

    public PacketFileWriter(PcapHandle handle, Path path) throws PcapNativeException, NotOpenException, IOException {
        this.path = path.toAbsolutePath();

        Path parentDir = this.path.getParent();
        if (parentDir != null && !Files.exists(parentDir)) {
            Files.createDirectories(parentDir); // Tworzy wszystkie brakujące foldery po drodze
        }

        this.dumper = handle.dumpOpen(this.path.toString());
    }
    public Path getPath(){
        return path;
    }
    public long writePacket(Packet packet) throws NotOpenException {
        long offset = currentOffset;
        dumper.dump(packet);
        currentOffset += 16 + packet.getRawData().length;
        return offset;
    }
    public long size() { return currentOffset; }

    public void flush() throws NotOpenException, PcapNativeException { dumper.flush(); }

    @Override
    public void close() { dumper.close(); }
}
