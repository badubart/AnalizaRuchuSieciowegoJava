package analizasieci.packetCapture.packetLayers;

import java.util.Map;

public interface ProtocolLayer {
    String getProtocolName();
    Map<String, String> getFields();
}