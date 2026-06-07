package analizasieci.packetCapture;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.Packet;

import java.io.Closeable;

public class PacketFileWriter implements Closeable {
    private final PcapDumper dumper;
    private long currentOffset = 24;

    public PacketFileWriter(PcapHandle handle, String path) throws PcapNativeException, NotOpenException {
        this.dumper = handle.dumpOpen(path);
    }

    public long writePacket(Packet packet) throws NotOpenException {
        long offset = currentOffset;
        dumper.dump(packet);
        currentOffset += 16 + packet.getRawData().length;
        return offset;
    }

    @Override
    public void close() { dumper.close(); }
}
