package analizasieci.packetCapture.packetLayers;

public enum Protocol {
    FTP(21, "File Transfer Protocol"),
    SSH(22, "Secure Shell"),
    Telnet(23, "Telnet"),
    SMTP(25, "Simple Mail Transfer Protocol"),
    HTTP(80, "Hypertext Transfer Protocol"),
    HTTP_ALT(8080, "HTTP Alternative"),
    HTTPS_ALT(8443, "HTTPS Alternative"),
    HTTPS(443, "HTTP Secure"),
    PortMapper(111,"Portmapper"),
    NFS(2049, "NFS"),
    DNS(53, "Domain Name System"),
    DHCP_SERVER(67, "Dynamic Host Configuration Protocol Server"),
    DHCP_CLIENT(68, "Dynamic Host Configuration Protocol Client"),
    SMTP_SUBMISSION(587, "SMTP Submission"),
    SMB_ALT(139, "Server Message Block"),
    SMB(445, "Server Message Block");

    private final int port;
    private final String description;

    Protocol(int port, String description) {
        this.port = port;
        this.description = description;
    }

    public int getPort() {
        return port;
    }

    public String getDescription() {
        return description;
    }
}
