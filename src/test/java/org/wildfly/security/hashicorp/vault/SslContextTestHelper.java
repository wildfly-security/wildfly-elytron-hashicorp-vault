/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * Test utility to build {@link SSLContext} from PEM files so that tests can verify
 * {@link VaultConnector} when it uses a configured with that SSLContext.
 */
public final class SslContextTestHelper {

    private static final Pattern PEM_BLOCK = Pattern.compile(
            "-----BEGIN ([^-]+)-----\\s*([\\s\\S]*?)\\s*-----END \\1-----",
            Pattern.MULTILINE);

    private SslContextTestHelper() {
    }

    /**
     * Create an SSLContext that trusts the given CA/trust PEM file (for HTTPS server verification).
     */
    public static SSLContext createTrustOnly(Path trustPemPath) throws Exception {
        TrustManager[] trustManagers = createTrustManagers(trustPemPath);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, trustManagers, new SecureRandom());
        return ctx;
    }

    /**
     * Create an SSLContext that trusts the given CA and uses the given client cert and key for client authentication.
     */
    public static SSLContext createWithClientAuth(Path trustPemPath, Path clientCertPemPath, Path clientKeyPemPath) throws Exception {
        TrustManager[] trustManagers = createTrustManagers(trustPemPath);
        KeyManager[] keyManagers = createKeyManagers(clientCertPemPath, clientKeyPemPath);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(keyManagers, trustManagers, new SecureRandom());
        return ctx;
    }

    private static TrustManager[] createTrustManagers(Path trustPemPath) throws Exception {
        List<Certificate> certs = readCertificatesFromPem(trustPemPath);
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        for (int i = 0; i < certs.size(); i++) {
            trustStore.setCertificateEntry("ca-" + i, certs.get(i));
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        return tmf.getTrustManagers();
    }

    private static KeyManager[] createKeyManagers(Path certPemPath, Path keyPemPath) throws Exception {
        List<Certificate> certs = readCertificatesFromPem(certPemPath);
        PrivateKey key = readPrivateKeyFromPem(keyPemPath);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setKeyEntry("client", key, new char[0], certs.toArray(new Certificate[0]));
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, new char[0]);
        return kmf.getKeyManagers();
    }

    private static List<Certificate> readCertificatesFromPem(Path path) throws Exception {
        String pem = Files.readString(path);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<Certificate> certs = new ArrayList<>();
        Matcher m = PEM_BLOCK.matcher(pem);
        while (m.find()) {
            String type = m.group(1);
            if ("CERTIFICATE".equals(type)) {
                byte[] der = Base64.getMimeDecoder().decode(m.group(2).replaceAll("\\s", ""));
                certs.add(cf.generateCertificate(new java.io.ByteArrayInputStream(der)));
            }
        }
        if (certs.isEmpty()) {
            throw new IllegalArgumentException("No CERTIFICATE block found in " + path);
        }
        return certs;
    }

    private static PrivateKey readPrivateKeyFromPem(Path path) throws Exception {
        String pem = Files.readString(path);
        Matcher m = PEM_BLOCK.matcher(pem);
        while (m.find()) {
            String type = m.group(1);
            if ("PRIVATE KEY".equals(type)) {
                byte[] der = Base64.getMimeDecoder().decode(m.group(2).replaceAll("\\s", ""));
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
                for (String algorithm : new String[] { "RSA", "EC" }) {
                    try {
                        return KeyFactory.getInstance(algorithm).generatePrivate(spec);
                    } catch (Exception ignored) {
                    }
                }
            }
        }
        throw new IllegalArgumentException("No PRIVATE KEY block found in " + path);
    }
}
