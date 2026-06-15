package analizasieci.network;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collections;
import java.util.Enumeration;

/**
 * Narzędzia sieciowe. Klasa pomocnicza – bez instancji.
 */
public final class NetworkUtils {

    private static final String FALLBACK_IPV4 = "127.0.0.1";

    private NetworkUtils() {
    }

    /**
     * Ustala lokalny adres IPv4 hosta.
     * <p>
     * Przegląda aktywne, niewirtualne interfejsy (pomijając pętlę zwrotną i adresy
     * link-local) i zwraca pierwszy znaleziony adres IPv4. Używany m.in. do określenia,
     * czy pakiet został wysłany, czy odebrany.
     *
     * @return lokalny adres IPv4 lub {@value #FALLBACK_IPV4}, gdy nie udało się go ustalić
     */
    public static String getLocalIpv4Address() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();

            for (NetworkInterface ni : Collections.list(interfaces)) {
                if (ni == null || !ni.isUp() || ni.isLoopback() || ni.isVirtual()) {
                    continue;
                }

                for (InetAddress addr : Collections.list(ni.getInetAddresses())) {
                    if (addr instanceof Inet4Address
                            && !addr.isLoopbackAddress()
                            && !addr.isLinkLocalAddress()) {
                        return addr.getHostAddress();
                    }
                }
            }
        } catch (SocketException ignored) {
            return FALLBACK_IPV4;
        }

        return FALLBACK_IPV4;
    }
}