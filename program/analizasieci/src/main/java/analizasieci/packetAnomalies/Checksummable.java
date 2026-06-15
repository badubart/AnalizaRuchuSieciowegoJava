package analizasieci.packetAnomalies;

import analizasieci.packetAnomalies.anomalies.ChecksumContext;

/**
 * Interfejs warstw protokołów, których poprawność można zweryfikować sumą kontrolną.
 */
public interface Checksummable {
    /**
     * Weryfikuje sumę kontrolną tej warstwy.
     *
     * @param ctx kontekst potrzebny do obliczeń (np. adresy do pseudo-nagłówka)
     * @return {@code true}, gdy suma kontrolna jest poprawna
     */
    public boolean verifyChecksum(ChecksumContext ctx);
}
