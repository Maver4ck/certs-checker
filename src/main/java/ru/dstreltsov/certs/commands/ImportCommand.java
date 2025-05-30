package ru.dstreltsov.certs.commands;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.stream.Collectors;

@CommandLine.Command(
    name = "import",
    description = "Import a list of key aliases from OLD keystore into NEW keystore"
)
public class ImportCommand implements Callable<Integer> {

    private static final Logger log = LoggerFactory.getLogger(ImportCommand.class);

    @CommandLine.Option(
        names = {"-o", "--old"},
        required = true,
        description = "Source keystore (.jks)"
    )
    private Path oldKeyStore;

    @CommandLine.Option(
        names = {"-n", "--new"},
        required = true,
        description = "Target keystore (.jks)"
    )
    private Path newKeyStore;

    @CommandLine.Option(
        names = {"-p", "--password"},
        defaultValue = "changeit",
        arity = "0..1"
    )
    private char[] storePassword;

    @CommandLine.Option(
        names = {"-i", "--input-file"},
        required = true,
        description = "Text file: one alias per line (no delimiters)"
    )
    private Path aliasesFile;

    @Override
    public Integer call() throws Exception {
        final KeyStore source = loadKeyStore(oldKeyStore);
        final KeyStore destination = loadKeyStore(newKeyStore);

        final Set<String> aliases = Files.readAllLines(aliasesFile).stream()
            .map(String::trim)
            .filter(s -> !s.isEmpty())
            .collect(Collectors.toUnmodifiableSet());

        for (String alias : aliases) {
            doImport(alias, source, destination);
        }

        try (OutputStream out = Files.newOutputStream(newKeyStore)) {
            destination.store(out, storePassword);
        }
        log.info("🔒 Saved keystore: {}", newKeyStore);
        return 0;
    }

    private void doImport(String alias, KeyStore source, KeyStore destination) throws KeyStoreException {
        if (!source.containsAlias(alias)) {
            log.error("⚠️  alias \"{}\" not found in {}", alias, oldKeyStore);
        } else if (destination.containsAlias(alias)) {
            log.error("⚠️ alias \"{}\" already exists in target {}, skipping", alias, newKeyStore);
        } else {
            final Certificate certificate = source.getCertificate(alias);
            destination.setCertificateEntry(alias, certificate);
            log.info("✅ imported alias \"{}\"", alias);
        }
    }

    private KeyStore loadKeyStore(Path path) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        final KeyStore keyStore = KeyStore.getInstance("JKS");
        try (InputStream in = Files.newInputStream(path)) {
            keyStore.load(in, storePassword);
        }
        return keyStore;
    }
}
