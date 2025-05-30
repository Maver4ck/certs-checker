package ru.dstreltsov.certs.helpers;

import java.time.Instant;

public record CertInfo(
    String alias,
    String fingerprint,
    String commonName,
    Instant notBefore,
    Instant notAfter
) {
}
