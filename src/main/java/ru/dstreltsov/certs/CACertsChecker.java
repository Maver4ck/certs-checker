package ru.dstreltsov.certs;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.Callable;

@CommandLine.Command(
    name = "cacerts-checker",
    mixinStandardHelpOptions = true,
    version = "1.0",
    description = "Compare two JKS cacerts and show identical, added, removed or changed certificates"
)
public class CACertsChecker implements Callable<Integer> {

    private static final Logger log = LoggerFactory.getLogger(CACertsChecker.class);
    private static final ObjectMapper mapper = new ObjectMapper();

    @CommandLine.Option(
        names = {"-o", "--old"},
        description = "Path to the OLD cacerts keystore (JKS format)",
        required = true
    )
    private Path oldKeystore;

    @CommandLine.Option(
        names = {"-n", "--new"},
        description = "Path to the NEW cacerts keystore (JKS format)",
        required = true
    )
    private Path newKeystore;

    @CommandLine.Option(
        names = {"-p", "--password"},
        description = "Password for both keystores (default: ${DEFAULT-VALUE})",
        defaultValue = "changeit",
        arity = "0..1"
    )
    private char[] storePassword;

    @CommandLine.Option(
        names = {"-t", "--tables"},
        description = "Which tables to display: ${COMPLETION-CANDIDATES} (comma-separated)",
        split = ",",
        defaultValue = "removed,added,changed"
    )
    private Table[] tables;

    @CommandLine.Option(
        names = {"-f", "--format"},
        description = "Output format: ${COMPLETION-CANDIDATES}",
        defaultValue = "console"
    )
    private Format format;

    public static void main(String[] args) {
        int exitCode = new CommandLine(new CACertsChecker()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        final Map<String, String> oldMap = extractKeyStoreData(oldKeystore.toString());
        final Map<String, String> newMap = extractKeyStoreData(newKeystore.toString());

        final Set<String> oldAliases = oldMap.keySet();
        final Set<String> newAliases = newMap.keySet();

        final List<Table> toShow = Arrays.asList(tables);
        final boolean showAll = toShow.contains(Table.all);

        final Map<String, Set<String>> resultMap = new LinkedHashMap<>();

        if (showAll || toShow.contains(Table.identical)) {
            final Set<String> identical = new TreeSet<>(oldAliases);
            identical.retainAll(newAliases);
            identical.removeIf(alias -> !Objects.equals(oldMap.get(alias), newMap.get(alias)));
            resultMap.put(Table.identical.name(), identical);
        }

        if (showAll || toShow.contains(Table.removed)) {
            final Set<String> removed = new TreeSet<>(oldAliases);
            removed.removeAll(newAliases);
            resultMap.put(Table.removed.name(), removed);
        }

        if (showAll || toShow.contains(Table.added)) {
            final Set<String> added = new TreeSet<>(newAliases);
            added.removeAll(oldAliases);
            resultMap.put(Table.added.name(), added);
        }

        if (showAll || toShow.contains(Table.changed)) {
            final Set<String> changed = new TreeSet<>(oldAliases);
            changed.retainAll(newAliases);
            changed.removeIf(alias -> Objects.equals(oldMap.get(alias), newMap.get(alias)));
            resultMap.put(Table.changed.name(), changed);
        }

        if (format == Format.console) {
            printToConsole(resultMap);
        }
        if (format == Format.json) {
            String json = mapper.writeValueAsString(resultMap);
            log.info(json);
        }

        return 0;
    }

    private void printToConsole(Map<String, Set<String>> resultMap) {
        resultMap.forEach((key, value) -> {
            log.info("=== {} ===", key);
            if (value.isEmpty()) {
                log.info("  <empty>");
            } else {
                value.forEach(val -> log.info("  {}", val));
            }
        });
    }

    private Map<String, String> extractKeyStoreData(String path)
        throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        final KeyStore keyStore = loadKeyStore(path);
        return buildAliasesMap(keyStore);
    }

    private Map<String, String> buildAliasesMap(KeyStore keyStore) throws NoSuchAlgorithmException, KeyStoreException, CertificateEncodingException {
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        final Enumeration<String> aliases = keyStore.aliases();

        final Map<String, String> aliasesMap = new HashMap<>();
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            final X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
            final byte[] hash = digest.digest(cert.getEncoded());
            aliasesMap.put(alias, Hex.encodeHexString(hash));
        }
        return aliasesMap;
    }

    private KeyStore loadKeyStore(String path) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        final KeyStore keyStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(path)) {
            keyStore.load(fis, storePassword);
        }
        return keyStore;
    }
}
