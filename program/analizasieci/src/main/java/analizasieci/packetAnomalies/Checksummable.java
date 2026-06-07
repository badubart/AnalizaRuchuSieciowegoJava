package analizasieci.packetAnomalies;

import analizasieci.packetAnomalies.anomalies.ChecksumContext;

public interface Checksummable {
    public boolean verifyChecksum(ChecksumContext ctx);
}
