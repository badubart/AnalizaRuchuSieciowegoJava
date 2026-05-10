package analizasieci.packetCapture;

public class PacketLookupRow {

    private int id;
    private String source;
    private String destination;
    private String protocol;
    private int length;
    private String info;

    public PacketLookupRow(int id, String source, String destination, String protocol, int length, String info) {
        this.id = id;
        this.source = source;
        this.destination = destination;
        this.protocol = protocol;
        this.length = length;
        this.info = info;
    }

    public int getId() {
        return id;
    }

    public String getSource() {
        return source;
    }

    public String getDestination() {
        return destination;
    }

    public String getProtocol() {
        return protocol;
    }

    public int getLength() {
        return length;
    }

    public String getInfo() {
        return info;
    }
}


