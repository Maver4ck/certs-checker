package ru.dstreltsov.certs.helpers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Printer {

    private static final Logger log = LoggerFactory.getLogger(Printer.class);
    private static final ObjectMapper MAPPER = new ObjectMapper().registerModule(new JavaTimeModule());

    public static void print(Map<String, List<CertInfo>> resultMap, Format format, Set<String> extraFields) throws JsonProcessingException {
        if (format == Format.console) {
            printToConsole(resultMap, extraFields);
        } else {
            printAsJson(resultMap, extraFields);
        }
    }

    private static void printAsJson(Map<String, List<CertInfo>> resultMap, Set<String> extraFields) throws JsonProcessingException {
        final Map<String, List<Map<String, Object>>> result = new LinkedHashMap<>();
        for (Map.Entry<String, List<CertInfo>> entry : resultMap.entrySet()) {
            final List<Map<String, Object>> rows = new ArrayList<>();
            for (CertInfo cert : entry.getValue()) {
                final Map<String, Object> m = new LinkedHashMap<>();
                m.put("alias", cert.alias());
                if (extraFields.contains("cn")) {
                    m.put("commonName", cert.commonName());
                }
                if (extraFields.contains("nb")) {
                    m.put("notBefore", cert.notBefore());
                }
                if (extraFields.contains("na")) {
                    m.put("notAfter", cert.notAfter());
                }
                rows.add(m);
            }
            result.put(entry.getKey(), rows);
        }
        log.info(MAPPER.writeValueAsString(result));
    }

    private static void printToConsole(Map<String, List<CertInfo>> resultMap, Set<String> extraFields) {
        resultMap.forEach((key, value) -> {
            log.info("=== {} ===", key);
            if (value.isEmpty()) {
                log.info("  <empty>");
            } else {
                value.forEach(certInfo -> {
                    final StringBuilder line = new StringBuilder()
                        .append("  alias=").append(certInfo.alias());
                    if (extraFields.contains("cn")) {
                        line.append(" cn=").append(certInfo.commonName());
                    }
                    if (extraFields.contains("nb")) {
                        line.append(" nb=").append(certInfo.notBefore());
                    }
                    if (extraFields.contains("na")) {
                        line.append(" na=").append(certInfo.notAfter());
                    }
                    log.info(line.toString());
                });
            }
        });
    }

    private Printer() {

    }
}
