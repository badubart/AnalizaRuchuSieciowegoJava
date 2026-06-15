package analizasieci.packetCapture.packetLayers;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Warstwa surowych danych – używana, gdy ładunku nie udało się rozpoznać jako
 * konkretny protokół. Prezentuje jedynie długość danych.
 */
public class RawData implements ProtocolLayer {

    private final byte[] rawData;

    public RawData(byte[] rawData) {
        this.rawData = rawData;
    }

    @Override
    public String getProtocolName() {
        return "Data";
    }

    @Override
    public Map<String, String> getFields() {
        Map<String, String> fields = new LinkedHashMap<>();

        fields.put("Payload Length", rawData.length + " bytes");
        return fields;
    }
}
