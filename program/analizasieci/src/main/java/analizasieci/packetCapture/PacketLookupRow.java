package analizasieci.packetCapture;

/**
 * Lekki, niezmienny model wiersza tabeli pakietów w UI.
 * <p>
 * Zawiera tylko dane potrzebne do wyświetlenia i filtrowania (adresy, protokół,
 * długość, info, MAC, flaga anomalii) oraz {@code fileOffset} – pozycję pełnego
 * pakietu w pliku pcap, używaną do doczytania szczegółów na żądanie.
 */
public class PacketLookupRow {
    private final int id;
    private final long fileOffset;

    // Lekkie pola potrzebne do wyświetlenia wiersza i filtrowania w UI
    private final String sourceIp;
    private final String destinationIp;
    private final String protocol;
    private final int length;
    private final String timestamp;
    private final String info;

    // Nowe pola dodane na potrzeby filtrowania
    private final String sourceMAC;
    private final String destinationMAC;
    private final boolean anomaly;

    public PacketLookupRow(int id, long fileOffset, String sourceIp, String destinationIp,
                           String protocol, int length, String timestamp, String info,
                           String sourceMAC, String destinationMAC, boolean anomaly) {
        this.id = id;
        this.fileOffset = fileOffset;
        this.sourceIp = sourceIp;
        this.destinationIp = destinationIp;
        this.protocol = protocol;
        this.length = length;
        this.timestamp = timestamp;
        this.info = info;
        this.sourceMAC = sourceMAC;
        this.destinationMAC = destinationMAC;
        this.anomaly = anomaly;
    }

    public int getId() {
        return id;
    }

    public long getFileOffset() {
        return fileOffset;
    }

    public String getSource() {
        return sourceIp;
    }

    public String getDestination() {
        return destinationIp;
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

    // --- Nowe gettery ---

    public String getSourceMAC() {
        return sourceMAC;
    }

    public String getDestinationMAC() {
        return destinationMAC;
    }

    public boolean isAnomaly() {
        return anomaly;
    }
}