package analizasieci.report;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.Map;

public final class HtmlReportGenerator {

    private HtmlReportGenerator() {
    }

    public static void writeReport(
            Path outputFile,
            Map<String, Integer> anomalyCount,
            int totalSent,
            int totalReceived,
            int countSent,
            int countReceived
    ) throws IOException {
        Files.writeString(
                outputFile,
                buildHtml(anomalyCount, totalSent, totalReceived, countSent, countReceived),
                StandardCharsets.UTF_8
        );
    }

    public static String buildHtml(
            Map<String, Integer> anomalyCount,
            int totalSent,
            int totalReceived,
            int countSent,
            int countReceived
    ) {
        int anomalyTotal = anomalyCount == null ? 0 : anomalyCount.values().stream().mapToInt(Integer::intValue).sum();
        String generatedAt = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>");
        html.append("<html lang=\"pl\">");
        html.append("<head>");
        html.append("<meta charset=\"UTF-8\">");
        html.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        html.append("<title>Raport analizy ruchu sieciowego</title>");
        html.append("<style>");
        html.append("body{font-family:Arial,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:24px;}");
        html.append(".wrap{max-width:1100px;margin:0 auto;}");
        html.append(".card{background:#111827;border:1px solid #1f2937;border-radius:14px;padding:20px;margin-bottom:20px;}");
        html.append(".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;}");
        html.append(".metric{background:#0b1220;border:1px solid #243047;border-radius:12px;padding:16px;}");
        html.append(".label{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#94a3b8;}");
        html.append(".value{font-size:28px;font-weight:700;margin-top:8px;color:#f8fafc;}");
        html.append("table{width:100%;border-collapse:collapse;}");
        html.append("th,td{padding:10px 12px;border-bottom:1px solid #243047;text-align:left;}");
        html.append("th{background:#0b1220;color:#93c5fd;}");
        html.append(".muted{color:#94a3b8;}");
        html.append(".ok{color:#86efac;}");
        html.append("</style>");
        html.append("</head>");
        html.append("<body><div class=\"wrap\">");
        html.append("<h1>Raport analizy ruchu sieciowego</h1>");
        html.append("<p class=\"muted\">Wygenerowano: ").append(escapeHtml(generatedAt)).append("</p>");

        html.append("<div class=\"card\"><h2>Podstawowe informacje</h2><div class=\"grid\">");
        html.append(metric("Pakiety wysłane", countSent));
        html.append(metric("Pakiety odebrane", countReceived));
        html.append(metric("Dane wysłane", formatBytes(totalSent)));
        html.append(metric("Dane odebrane", formatBytes(totalReceived)));
        html.append(metric("Wszystkie anomalie", anomalyTotal));
        html.append("</div></div>");

        html.append("<div class=\"card\"><h2>Wystąpienia anomalii</h2>");
        if (anomalyCount == null || anomalyCount.isEmpty()) {
            html.append("<p class=\"ok\">Nie wykryto anomalii.</p>");
        } else {
            html.append("<table><thead><tr><th>Typ anomalii</th><th>Liczba wystąpień</th></tr></thead><tbody>");
            anomalyCount.entrySet().stream()
                    .sorted(Comparator.comparing(Map.Entry<String, Integer>::getKey, String.CASE_INSENSITIVE_ORDER))
                    .forEach(entry -> {
                        html.append("<tr>");
                        html.append("<td>").append(escapeHtml(entry.getKey())).append("</td>");
                        html.append("<td>").append(entry.getValue()).append("</td>");
                        html.append("</tr>");
                    });
            html.append("</tbody></table>");
        }
        html.append("</div>");
        html.append("</div></body></html>");
        return html.toString();
    }

    private static String metric(String label, Object value) {
        return "<div class=\"metric\"><div class=\"label\">" + escapeHtml(label) + "</div><div class=\"value\">" + escapeHtml(String.valueOf(value)) + "</div></div>";
    }

    private static String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        double kb = bytes / 1024.0;
        if (kb < 1024) {
            return String.format("%.2f KB", kb);
        }
        double mb = kb / 1024.0;
        if (mb < 1024) {
            return String.format("%.2f MB", mb);
        }
        return String.format("%.2f GB", mb / 1024.0);
    }

    private static String escapeHtml(String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        return text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}