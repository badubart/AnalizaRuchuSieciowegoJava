package analizasieci.packetCapture;


import analizasieci.packetCapture.packetLayers.ProtocolLayer;

import java.util.ArrayList;
import java.util.List;

public class MyPacket
{
    private byte[] rawData;
    private String timeStamp;
    private int packetLength;
    private String sourceMAC = "";
    private String destinationMAC = "";
    private String sourceIp = "";
    private String destinationIp = "";
    private int sourcePort = -1;
    private int destinationPort = -1;
    private String highestProtocolName = "";
    private final List<ProtocolLayer> layers = new ArrayList<>();

    public String getTimeStamp(){
        return timeStamp;
    }
    public int getPacketLength(){
        return packetLength;
    }
    public String getSourceMAC(){
        return sourceMAC;
    }
    public String getDestinationMAC(){
        return destinationMAC;
    }
    public String getSourceIp(){
        return sourceIp;
    }
    public String getDestinationIp(){
        return destinationIp;
    }
    public int getSourcePort(){
        return sourcePort;
    }
    public int getDestinationPort(){
        return destinationPort;
    }
    public String getHighestProtocolName() {
        return highestProtocolName;
    }
    public void setTimeStamp(String timeStamp){
        this.timeStamp = timeStamp;
    }
    public void setPacketLength(int packetLength){
        this.packetLength = packetLength;
    }
    public void setSourceMAC(String sourceMAC){
        this.sourceMAC = sourceMAC;
    }
    public void setDestinationMAC(String destinationMAC){
        this.destinationMAC = destinationMAC;
    }
    public void setSourceIp(String sourceIp){
        this.sourceIp = sourceIp;
    }
    public void setDestinationIp(String destinationIp){
        this.destinationIp=destinationIp;
    }
    public void setSourcePort(int sourcePort){
        this.sourcePort = sourcePort;
    }
    public void setDestinationPort(int destinationPort){
        this.destinationPort = destinationPort;
    }
    public void setHighestProtocolName(String highestProtocolName){
        this.highestProtocolName = highestProtocolName;
    }
    public void addLayer(ProtocolLayer layer){
        layers.add(layer);
    }
    public List<ProtocolLayer> getLayers(){
        return layers;
    }



    public byte[] getRawData() {
        return rawData;
    }

    public void setRawData(byte[] rawData) {
        this.rawData = rawData;
    }
    public String getHexDump() {
        if (rawData == null || rawData.length == 0) {
            return "Brak danych pakietu.";
        }

        StringBuilder dump = new StringBuilder();

        for (int i = 0; i < rawData.length; i += 16) {
            dump.append(String.format("%04X  ", i));

            StringBuilder hexPart = new StringBuilder();
            StringBuilder asciiPart = new StringBuilder();
            for (int j = 0; j < 16; j++) {
                if (i + j < rawData.length) {
                    byte b = rawData[i + j];

                    hexPart.append(String.format("%02X ", b));

                    if (j == 7) {
                        hexPart.append(" ");
                    }

                    char c = (char) b;
                    if (c >= 32 && c <= 126) {
                        asciiPart.append(c);
                    } else {
                        asciiPart.append('.');
                    }
                } else {
                    hexPart.append("   ");
                    if (j == 7) {
                        hexPart.append(" ");
                    }
                }
            }
            dump.append(hexPart.toString()).append("  ").append(asciiPart.toString()).append("\n");
        }

        return dump.toString();
    }
}
