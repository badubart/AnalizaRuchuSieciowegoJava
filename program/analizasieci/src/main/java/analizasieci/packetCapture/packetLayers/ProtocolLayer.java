package analizasieci.packetCapture.packetLayers;

import java.util.Map;

/**
 * Wspólny interfejs pojedynczej warstwy protokołu w pakiecie.
 * Implementacje (np. {@code L3IPv4}, {@code L4TCP}, {@code L7HTTP}) udostępniają
 * nazwę protokołu oraz zbiór pól prezentowanych w drzewie szczegółów pakietu.
 */
public interface ProtocolLayer {
    /** @return czytelna nazwa protokołu tej warstwy (np. "IPv4", "TCP"). */
    String getProtocolName();
    /** @return uporządkowana mapa: nazwa pola → wartość, do wyświetlenia w UI. */
    Map<String, String> getFields();
}