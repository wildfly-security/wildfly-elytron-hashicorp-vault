/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.hashicorp.vault.auth.TlsCertAuthConfig;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.VaultException;
import io.smallrye.certs.CertificateFiles;
import io.smallrye.certs.CertificateGenerator;
import io.smallrye.certs.CertificateRequest;
import io.smallrye.certs.Format;
import io.smallrye.certs.PemCertificateFiles;

/**
 * Negative TLS tests with mutual TLS enforcement ({@code tls_require_and_verify_client_cert = true}).
 * Vault rejects connections at the TLS handshake level when a valid client certificate is not presented.
 */
public class VaultConnectorMutualTlsTestCase {

    private VaultContainerHttps<?> vaultTestContainer;
    private SslConfig permissibleSslConfig;

    @BeforeEach
    public void beforeEach() throws Exception {
        vaultTestContainer = new VaultContainerHttps<>("hashicorp/vault:1.13", true)
                .withVaultToken("myroot")
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 ttl=30m top_secret=password123"
                );

        new TlsCertAuthConfig.Builder(vaultTestContainer.getClientCertificateFiles())
                .policies("admin")
                .build()
                .configure(vaultTestContainer);

        vaultTestContainer.start();

        permissibleSslConfig = new SslConfig()
                .pemFile(vaultTestContainer.getHttpsTrustFile().toFile())
                .clientPemFile(vaultTestContainer.getClientCertificateFiles().clientCertFile().toFile())
                .clientKeyPemFile(vaultTestContainer.getClientCertificateFiles().clientKeyFile().toFile())
                .verify(true)
                .build();
    }

    @AfterEach
    public void cleanup() {
        if (vaultTestContainer != null) {
            vaultTestContainer.stop();
        }
    }

    /**
     * Helper method to get a secret value using the new alias-based API.
     */
    private String getSecret(VaultConnector connector, String path, String key) throws CredentialStoreException {
        String secretPath = path.substring(path.indexOf('/') + 1);
        String aliasString = "#" + secretPath + "?" + key;
        VaultAlias alias = VaultAlias.parse(aliasString, "KVv2", "secret");
        Map<String, Object> data = connector.getSecretData(alias);
        if (data == null) {
            return null;
        }
        return VaultKeyPathOperations.resolveKeyPath(data, key);
    }

    /**
     * Verify that Vault rejects the TLS handshake when a client certificate signed by a different CA
     * is presented. The server requires mutual TLS and the client cert CA is not in {@code tls_client_ca_file}.
     */
    @Test
    public void testMutualTlsRejectsUntrustedClientCert() throws Exception {
        Path wrongCertDir = Files.createTempDirectory("wrong_mtls_certs");
        try {
            CertificateRequest request = new CertificateRequest()
                    .withName("wrong")
                    .withPassword("secret")
                    .withClientCertificate()
                    .withFormat(Format.PEM);
            List<CertificateFiles> wrongCerts = new CertificateGenerator(wrongCertDir, true).generate(request);
            PemCertificateFiles wrongPem = (PemCertificateFiles) wrongCerts.stream()
                    .filter(f -> f instanceof PemCertificateFiles).findFirst().get();

            SslConfig wrongClientConfig = new SslConfig()
                    .pemFile(vaultTestContainer.getHttpsTrustFile().toFile())
                    .clientPemFile(wrongPem.clientCertFile().toFile())
                    .clientKeyPemFile(wrongPem.clientKeyFile().toFile())
                    .verify(true)
                    .build();

            VaultConnector connector = new VaultConnector(
                    vaultTestContainer.composeHttpsHostAddress(), "", "secret/testing1", wrongClientConfig, true);
            connector.configure();
            assertThrows(CredentialStoreException.class, () -> getSecret(connector, "secret/testing1", "top_secret"));
        } finally {
            VaultTestUtils.cleanupDir(wrongCertDir);
        }
    }

    /**
     * Verify that Vault rejects the TLS handshake when no client certificate is presented
     * and mutual TLS is required.
     */
    @Test
    public void testMutualTlsRejectsNoClientCert() throws Exception {
        SslConfig trustOnlyConfig = new SslConfig()
                .pemFile(vaultTestContainer.getHttpsTrustFile().toFile())
                .verify(true)
                .build();

        VaultConnector connector = new VaultConnector(
                vaultTestContainer.composeHttpsHostAddress(), "", "secret/testing1", trustOnlyConfig, true);
        connector.configure();
        assertThrows(CredentialStoreException.class, () -> getSecret(connector, "secret/testing1", "top_secret"));
    }

    /**
     * Verify that Vault rejects the TLS handshake when an untrusted client certificate is presented
     * via a custom {@link SSLContext} / {@link java.net.http.HttpClient} code path.
     */
    @Test
    public void testMutualTlsRejectsUntrustedClientCertViaHttpClient() throws Exception {
        Path wrongCertDir = Files.createTempDirectory("wrong_mtls_httpclient_certs");
        try {
            CertificateRequest request = new CertificateRequest()
                    .withName("wrong")
                    .withPassword("secret")
                    .withClientCertificate()
                    .withFormat(Format.PEM);
            List<CertificateFiles> wrongCerts = new CertificateGenerator(wrongCertDir, true).generate(request);
            PemCertificateFiles wrongPem = (PemCertificateFiles) wrongCerts.stream()
                    .filter(f -> f instanceof PemCertificateFiles).findFirst().get();

            SSLContext wrongSslContext = SslContextTestHelper.createWithClientAuth(
                    vaultTestContainer.getHttpsTrustFile(),
                    wrongPem.clientCertFile(),
                    wrongPem.clientKeyFile());

            SslConfig sslConfig = new SslConfig().verify(true).build();
            VaultConnector connector = new VaultConnector(
                    vaultTestContainer.composeHttpsHostAddress(), "", null, sslConfig, true, wrongSslContext);
            connector.configure();
            assertThrows(CredentialStoreException.class, () -> getSecret(connector, "secret/testing1", "top_secret"));
        } finally {
            VaultTestUtils.cleanupDir(wrongCertDir);
        }
    }
}
