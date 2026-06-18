/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.jboss.logging.Logger;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.hashicorp.vault.logging.JbossLoggingLogConsumer;

import io.smallrye.certs.CertificateFiles;
import io.smallrye.certs.CertificateGenerator;
import io.smallrye.certs.CertificateRequest;
import io.smallrye.certs.Format;
import io.smallrye.certs.PemCertificateFiles;

/**
 * Represents a {@link VaultContainer} running with a secured interface.
 * This container is available at port 8400
 * See VAULT_CONFIG for details.
 */
public class VaultContainerHttps<SELF extends VaultContainerHttps<SELF>> extends VaultContainer<SELF> {

    private static final int HTTPS_PORT = 8400;

    private static final String VAULT_CERT_NAME = "vault.crt";
    private static final String VAULT_CERT_KEY_NAME = "vault.key";
    private static final String CLIENT_CA_CERT_NAME = "client-ca.crt";

    private static final Path VAULT_CERT_CONTAINER_PATH = Path.of("/vault/certs");

    private static String vaultConfig(boolean requireMutualTls) {
        return String.format(
            "listener \"tcp\" {\n" +
            "  address             = \"0.0.0.0:%d\"\n" +
            "  tls_cert_file       = \"%s\"\n" +
            "  tls_key_file        = \"%s\"\n" +
            "  tls_client_ca_file  = \"%s\"\n" +
            "  tls_require_and_verify_client_cert = %s\n" +
            "}\n" +
            "\n" +
            "storage \"file\" {\n" +
            "  path = \"/vault/data\"\n" +
            "}\n" +
            "\n" +
            "ui = false\n" +
            "\n" +
            "disable_mlock = true\n" +
            "api_addr = \"https://127.0.0.1:%d\"\n",
            HTTPS_PORT,
            VAULT_CERT_CONTAINER_PATH.resolve(VAULT_CERT_NAME).toAbsolutePath(),
            VAULT_CERT_CONTAINER_PATH.resolve(VAULT_CERT_KEY_NAME).toAbsolutePath(),
            VAULT_CERT_CONTAINER_PATH.resolve(CLIENT_CA_CERT_NAME).toAbsolutePath(),
            requireMutualTls,
            HTTPS_PORT
        );
    }

    //custom admin policy configuration - grants all rights the root policy has
    private static final String ADMIN_POLICY_CONFIG = "path \"*\" {\n" +
            "  capabilities = [\"create\",\"read\",\"update\",\"delete\",\"list\",\"sudo\"]\n" +
            "}";

    private static final String ADMIN_POLICY_CONFIG_NAME = "admin-policy.hcl";
    private static final String VAULT_CONFIG_NAME = "config.hcl";

    private static final Path VAULT_CONFIG_CONTAINER_PATH = Path.of("/vault/config");

    //certificate chain used by TLS listener
    private final Path generatedCertificatesDir;
    private static PemCertificateFiles serverPemCertificateFiles;

    //certificate chain used for authenticating clients
    private final Path generatedClientCertificatesDir;
    private static PemCertificateFiles clientPemCertificateFiles;

    //directories mounted/copied to the container
    private final Path mountedVaultCertsDir;
    private final Path mountedVaultConfigDir;

    /**
     * Create a Vault container with HTTPS enabled on port 8400. Client certificate is not required.
     */
    public VaultContainerHttps(String dockerImageName) throws IOException {
        this(dockerImageName, false);
    }

    /**
     * Create a Vault container with HTTPS enabled on port 8400.
     *
     * @param requireMutualTls when {@code true}, Vault sets {@code tls_require_and_verify_client_cert = true}
     *        and rejects TLS connections that do not present a valid client certificate.
     *        When {@code false}, client certificates are optional -- connections without a client cert
     *        are accepted at the TLS level, but cert-based authentication may still fail at the Vault auth level.
     *        Health check uses the HTTP dev port (8200) when mutual TLS is required, since the HTTPS port
     *        would reject the health probe.
     */
    public VaultContainerHttps(String dockerImageName, boolean requireMutualTls) throws IOException {
        super(dockerImageName);

        final MountableFile certs;
        final MountableFile config;

        this.generatedCertificatesDir = Files.createTempDirectory("generated_certificates");
        this.generatedClientCertificatesDir = Files.createTempDirectory("generated_client_certificates");
        this.mountedVaultCertsDir = Files.createTempDirectory("vault_certs");
        this.mountedVaultConfigDir = Files.createTempDirectory("vault_config");

        try {
            prepareCertificatesForClientAuthentication(this.generatedClientCertificatesDir, this.mountedVaultCertsDir);
            prepareCertificatesForHttps(this.generatedCertificatesDir, this.mountedVaultCertsDir);
            certs = MountableFile.forHostPath(this.mountedVaultCertsDir, 0777);

            config = MountableFile.forHostPath(prepareVaultConfig(this.mountedVaultConfigDir, requireMutualTls), 0777);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        this.withCopyFileToContainer(certs, VAULT_CERT_CONTAINER_PATH.toAbsolutePath().toString())
                .withCopyFileToContainer(config, VAULT_CONFIG_CONTAINER_PATH.toAbsolutePath().toString())
                .withExposedPorts(8200, HTTPS_PORT)
                .withLogConsumer(new JbossLoggingLogConsumer(Logger.getLogger("HTTPS_VAULT_CONTAINER")))
                .withInitCommand("policy write admin " + VAULT_CONFIG_CONTAINER_PATH.resolve(ADMIN_POLICY_CONFIG_NAME).toAbsolutePath())
                .withCommand("server", "-dev");

        if (requireMutualTls) {
            this.setWaitStrategy(Wait.forHttp("/v1/sys/health")
                    .forPort(8200)
                    .forResponsePredicate(response -> response.contains("\"initialized\":true")));
        } else {
            this.setWaitStrategy(Wait.forHttps("/v1/sys/health")
                    .forPort(HTTPS_PORT)
                    .allowInsecure()
                    .forResponsePredicate(response -> response.contains("\"initialized\":true")));
        }
    }

    private static void prepareCertificatesForHttps(final Path certTmpDir, final Path vaultTmpCertDir) throws Exception {
        final CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withPassword("secret")
                .withClientCertificate()
                .withFormat(Format.PEM)
                .withFormat(Format.JKS);

        final List<CertificateFiles> certificateFiles = new CertificateGenerator(certTmpDir, true).generate(request);

        serverPemCertificateFiles = (PemCertificateFiles) certificateFiles.stream()
                .filter(files -> files instanceof PemCertificateFiles).findFirst().get();

        final Path certPath = serverPemCertificateFiles.certFile();
        final Path keyPath  = serverPemCertificateFiles.keyFile();

        Files.copy(certPath, vaultTmpCertDir.resolve(VAULT_CERT_NAME), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        Files.copy(keyPath,  vaultTmpCertDir.resolve(VAULT_CERT_KEY_NAME), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }

    /**
     * Generate certificate chain for client authentication method.
     * We need to do that here because the container/vault must trust the issuer of client certificate.
     * See tls_client_ca_file vault configuration key where the CA cert is set.
     * @param certTmpDir directory where to generate the chain
     * @param vaultTmpCertDir target directory where to copy final client certificate and key
     */
    private static void prepareCertificatesForClientAuthentication(final Path certTmpDir, final Path vaultTmpCertDir) throws Exception {
        final CertificateRequest request = new CertificateRequest()
                .withName("test")
                .withPassword("secret")
                .withClientCertificate()
                .withFormat(Format.PEM)
                .withFormat(Format.JKS);

        final List<CertificateFiles> certificateFiles = new CertificateGenerator(certTmpDir, true).generate(request);

        clientPemCertificateFiles = (PemCertificateFiles) certificateFiles.stream()
                .filter(files -> files instanceof PemCertificateFiles).findFirst().get();

        Files.copy(clientPemCertificateFiles.trustFile(), vaultTmpCertDir.resolve(CLIENT_CA_CERT_NAME), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }

    /**
     * Write configuration strings to files
     * @param vaultConfigDir where to copy hcl configuration files
     */
    private static Path prepareVaultConfig(final Path vaultConfigDir, boolean requireMutualTls) throws IOException {
        final Path vaultConfigFile = vaultConfigDir.resolve(VAULT_CONFIG_NAME);
        final Path adminPolicyConfigFile = vaultConfigDir.resolve(ADMIN_POLICY_CONFIG_NAME);
        Files.writeString(vaultConfigFile, vaultConfig(requireMutualTls));
        Files.writeString(adminPolicyConfigFile, ADMIN_POLICY_CONFIG);
        return vaultConfigDir;
    }

    /**
     * Retrieve HTTPS address of the Vault
     */
    public String composeHttpsHostAddress() {
        return String.format("https://%s:%s", this.getHost(), this.getMappedPort(HTTPS_PORT));
    }

    /**
     * Retrieve CA certificate which was used to issue certificate the Vault's TLS listener uses to establish HTTPS
     * connection
     * @return CA certificate/trust file
     */
    public Path getHttpsTrustFile() {
        return serverPemCertificateFiles.trustFile();
    }

    /**
     * When we generate custom certificates, we need to tell the Vault which CA to trust - this is configured in
     * tls_client_ca_file.
     * By having the container class to generate the chain we can ensure that proper trust is established everywhere.
     * @return Whole chain of generated client certificates
     */
    public PemCertificateFiles getClientCertificateFiles() {
        return clientPemCertificateFiles;
    }

    @Override
    public void close() {
        super.close();
        VaultTestUtils.cleanupDir(this.generatedCertificatesDir);
        VaultTestUtils.cleanupDir(this.generatedClientCertificatesDir);
        VaultTestUtils.cleanupDir(this.mountedVaultCertsDir);
        VaultTestUtils.cleanupDir(this.mountedVaultConfigDir);
    }

    @Override
    public String toString() {
        return String.format("VaultContainerHttps{image=%s, httpsPort=%d, certsDir=%s, configDir=%s}",
                getDockerImageName(), HTTPS_PORT, mountedVaultCertsDir, mountedVaultConfigDir);
    }
}
