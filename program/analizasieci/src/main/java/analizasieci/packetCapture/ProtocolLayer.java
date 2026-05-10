package analizasieci.packetCapture;

import java.util.LinkedHashMap;

public interface ProtocolLayer {
    String getProtocolName();
    LinkedHashMap<String, String> getFields();
}