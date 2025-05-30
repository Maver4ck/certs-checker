package ru.dstreltsov.certs.commands;

import org.apache.commons.codec.binary.Hex;
import picocli.CommandLine;
import ru.dstreltsov.certs.CACertsChecker;
import ru.dstreltsov.certs.helpers.CertInfo;
import ru.dstreltsov.certs.helpers.Format;
import ru.dstreltsov.certs.helpers.Printer;
import ru.dstreltsov.certs.helpers.Table;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;

@CommandLine.Command(
    name = "compare",
    description = "Compare two JKS cacerts and show identical / added / removed / changed"
)
public class CompareCommand implements Callable<Integer> {

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
    private Set<Table> tables;

    @CommandLine.Option(
        names = {"-f", "--format"},
        description = "Output format: ${COMPLETION-CANDIDATES}",
        defaultValue = "console"
    )
    private Format format;

    @CommandLine.Option(
        names = {"-x", "--extra"},
        description = "Additional certificate fields to show: cn, nb, na (comma-separated)",
        split = ",",
        defaultValue = "nb"
    )
    private Set<String> extraFields;

    public static void main(String[] args) {
        int exitCode = new CommandLine(new CACertsChecker()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        final Map<String, CertInfo> oldMap = extractKeyStoreData(oldKeystore);
        final Map<String, CertInfo> newMap = extractKeyStoreData(newKeystore);

        final boolean showAll = tables.contains(Table.all);

        final Map<String, List<CertInfo>> resultMap = new LinkedHashMap<>();

        if (showAll || tables.contains(Table.identical)) {
            final List<CertInfo> identical = oldMap.keySet().stream()
                .filter(newMap::containsKey)
                .filter(alias -> oldMap.get(alias).fingerprint().equals(newMap.get(alias).fingerprint()))
                .map(oldMap::get)
                .sorted(Comparator.comparing(CertInfo::alias))
                .toList();
            resultMap.put(Table.identical.name(), identical);
        }

        if (showAll || tables.contains(Table.removed)) {
            final List<CertInfo> removed = oldMap.keySet().stream()
                .filter(alias -> !newMap.containsKey(alias))
                .map(oldMap::get)
                .sorted(Comparator.comparing(CertInfo::alias))
                .toList();
            resultMap.put(Table.removed.name(), removed);
        }

        if (showAll || tables.contains(Table.added)) {
            final List<CertInfo> added = newMap.keySet().stream()
                .filter(alias -> !oldMap.containsKey(alias))
                .map(newMap::get)
                .sorted(Comparator.comparing(CertInfo::alias))
                .toList();
            resultMap.put(Table.added.name(), added);
        }

        if (showAll || tables.contains(Table.changed)) {
            final List<CertInfo> changed = oldMap.keySet().stream()
                .filter(newMap::containsKey)
                .filter(alias -> !oldMap.get(alias).fingerprint().equals(newMap.get(alias).fingerprint()))
                .map(newMap::get)
                .sorted(Comparator.comparing(CertInfo::alias))
                .toList();
            resultMap.put(Table.changed.name(), changed);
        }

        Printer.print(resultMap, format, extraFields);

        return 0;
    }

    private Map<String, CertInfo> extractKeyStoreData(Path path)
        throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        final KeyStore keyStore = loadKeyStore(path);
        return buildAliasesMap(keyStore);
    }

    private Map<String, CertInfo> buildAliasesMap(KeyStore keyStore) throws NoSuchAlgorithmException, KeyStoreException, CertificateEncodingException {
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");

        final Map<String, CertInfo> result = new HashMap<>();
        for (Enumeration<String> enumeration = keyStore.aliases(); enumeration.hasMoreElements(); ) {
            final String alias = enumeration.nextElement();
            final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);

            final String fingerprint = Hex.encodeHexString(digest.digest(certificate.getEncoded()));
            final String commonName = getCommonName(certificate);
            final Instant notBefore = certificate.getNotBefore().toInstant();
            final Instant notAfter = certificate.getNotAfter().toInstant();

            result.put(alias, new CertInfo(alias, fingerprint, commonName, notBefore, notAfter));
        }
        return result;
    }

    private static String getCommonName(X509Certificate certificate) {
        final String subject = certificate.getSubjectX500Principal().getName();
        return Arrays.stream(subject.split(","))
            .filter(s -> s.startsWith("CN="))
            .map(s -> s.substring(3))
            .findFirst()
            .orElse("");
    }

    private KeyStore loadKeyStore(Path path) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        final KeyStore keyStore = KeyStore.getInstance("JKS");
        try (InputStream in = Files.newInputStream(path)) {
            keyStore.load(in, storePassword);
        }
        return keyStore;
    }
}
