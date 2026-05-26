package analizasieci.packetCapture;

public class PacketLookupRow {
    private final  MyPacket packet;
    private final int id;

    public PacketLookupRow(int id, MyPacket packet) {
        this.id = id;
        this.packet = packet;
    }

    public int getId() {
        return id;
    }

    public MyPacket getPacket(){
        return packet;
    }
    public String getSource() {
        return packet.getSourceIp();
    }

    public String getDestination() {
        return packet.getDestinationIp();
    }

    public String getProtocol() {
        return packet.getHighestProtocolName();
    }

    public int getLength() {
        return packet.getPacketLength();
    }

    public String getInfo() {
        return packet.getTimeStamp();
    }
}


