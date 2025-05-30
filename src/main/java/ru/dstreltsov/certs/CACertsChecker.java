package ru.dstreltsov.certs;

import picocli.CommandLine;
import ru.dstreltsov.certs.commands.CompareCommand;
import ru.dstreltsov.certs.commands.ImportCommand;

@CommandLine.Command(
    name = "cacerts-checker",
    mixinStandardHelpOptions = true,
    version = "1.0",
    description = "Compare or import certs in JKS keystores",
    subcommands = {
        CompareCommand.class,
        ImportCommand.class
    }
)
public class CACertsChecker {

    public static void main(String[] args) {
        final int exitCode = new CommandLine(new CACertsChecker()).execute(args);
        System.exit(exitCode);
    }
}
