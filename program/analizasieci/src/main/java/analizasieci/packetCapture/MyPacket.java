package analizasieci.packetCapture;


import analizasieci.packetCapture.packetLayers.ProtocolLayer;

import java.util.ArrayList;
import java.util.List;

public class MyPacket
{
    private String timeStamp;
    private int packetLength;
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
}
