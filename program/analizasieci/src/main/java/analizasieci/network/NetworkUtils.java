package analizasieci.network;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collections;
import java.util.Enumeration;

public final class NetworkUtils {

    private static final String FALLBACK_IPV4 = "127.0.0.1";

    private NetworkUtils() {
    }

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