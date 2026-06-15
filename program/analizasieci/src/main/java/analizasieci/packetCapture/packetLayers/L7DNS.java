package analizasieci.packetCapture.packetLayers;

import org.pcap4j.packet.DnsPacket;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Warstwa DNS. Udostępnia identyfikator transakcji, opcode, flagę odpowiedzi,
 * liczbę zapytań i odpowiedzi oraz nazwę pierwszej odpytywanej domeny.
 */
public class L7DNS implements ProtocolLayer{
    private final DnsPacket packet;
    public L7DNS(DnsPacket packet){
        this.packet = packet;
    }
    @Override
    public String getProtocolName() {
        return "Domain Name System (DNS)";
    }

    @Override
    public Map<String, String> getFields() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("TransactionID", String.format("0x%04x", packet.getHeader().getId()));
        fields.put("OpCode", packet.getHeader().getOpCode().name());
        fields.put("Response", packet.getHeader().isResponse() ? "True" : "False");
        fields.put("QuestionCount", String.valueOf(packet.getHeader().getQdCountAsInt()));
        fields.put("AnswerCount", String.valueOf(packet.getHeader().getAnCountAsInt()));

        // Opcjonalnie: wyciągnięcie nazw, o które pytano (pierwsze zapytanie)
        if (!packet.getHeader().getQuestions().isEmpty()) {
            fields.put("Domain", packet.getHeader().getQuestions().get(0).getQName().getName());
        }

        return fields;
    }

}
