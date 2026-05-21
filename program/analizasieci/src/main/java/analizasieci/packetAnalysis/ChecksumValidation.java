package analizasieci.packetAnalysis;

import java.nio.ByteBuffer;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

public class ChecksumValidation {


    public String validateTCP(Packet packet)
    {
        TcpPacket tcp = packet.get(TcpPacket.class);
        byte[] tcpSeg = tcp.getRawData().clone();
        int tcpLen = tcpSeg.length;
        byte[] srcAddress = packet.get(IpV4Packet.class).getHeader().getSrcAddr().getAddress().clone();
        byte[] destAddress = packet.get(IpV4Packet.class).getHeader().getDstAddr().getAddress().clone();


        if(tcpSeg.length<18)
        {
            return "TCP too short";
        }
        else
        {
            tcpSeg[16]=0;
            tcpSeg[17]=0;
            ByteBuffer mySum = ByteBuffer.allocate(12+tcpLen);
            mySum.put(srcAddress);
            mySum.put(destAddress);
            mySum.put((byte) 0);
            mySum.put((byte) 6);
            mySum.putShort((short) tcpSeg.length);
            mySum.put(tcpSeg);

            short myCheckSum = calculateCheckSum(mySum.array());

            if (myCheckSum == tcp.getHeader().getChecksum())
            {
                return String.format("0x%04X", myCheckSum & 0xFFFF)+" Valid";
            }
            else
            {
                return String.format("0x%04X", myCheckSum & 0xFFFF)+" Invalid";
            }
        }
    }
//    public String validateUdp(Packet packet)
//    {
//        UdpPacket udp = packet.get(UdpPacket.class);
//        byte[] udpSeg = udp.getRawData().clone();
//        int tcpLen = udpSeg.length;
//        byte[] srcAddress = packet.get(IpV4Packet.class).getHeader().getSrcAddr().getAddress().clone();
//        byte[] destAddress = packet.get(IpV4Packet.class).getHeader().getDstAddr().getAddress().clone();
//
//
//        if(udpSeg.length<18)
//        {
//            return "UDP too short";
//        }
//        else
//        {
//            udpSeg[16]=0;
//            udpSeg[17]=0;
//            ByteBuffer mySum = ByteBuffer.allocate(12+tcpLen);
//            mySum.put(srcAddress);
//            mySum.put(destAddress);
//            mySum.put((byte) 0);
//            mySum.put((byte) 6);
//            mySum.putShort((short) udpSeg.length);
//            mySum.put(udpSeg);
//
//            short myCheckSum = calculateCheckSum(mySum.array());
//
//            if (myCheckSum == udp.getHeader().getChecksum())
//            {
//                return String.format("0x%04X", myCheckSum & 0xFFFF)+" Valid";
//            }
//            else
//            {
//                return String.format("0x%04X", myCheckSum & 0xFFFF)+" Invalid";
//            }
//        }
//    }


    public short calculateCheckSum(byte [] data)
    {
        long sum=0;
        int i=0;

        while(i< data.length-1)
        {
            int value = ((data[i]<<8)&0xFF00)|(data[i+1]&0xFF);
            sum+=value;
            while((sum & 0xFFFF0000)!=0)
            {
                sum=(sum & 0xFFFF)+(sum>>16);
            }
            i+=2;

        }

        if(i<data.length)
        {
            int value = (data[i]<<8)&0xFF00;
            sum+=value;
            while((sum & 0xFFFF0000)!=0)
            {
                sum=(sum & 0xFFFF)+(sum>>16);
            }
        }
        return (short)~sum;
    }
}
