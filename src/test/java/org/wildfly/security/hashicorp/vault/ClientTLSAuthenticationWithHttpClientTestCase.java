/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.VaultException;

/**
 * Tests that {@link VaultConnector} works over HTTPS when an SSLContext is passed.
 * This verifies the code path in {@link VaultConnector#configure()}
 * that builds an HttpClient with the provided SSLContext and passes it to VaultConfig.
 */
public class ClientTLSAuthenticationWithHttpClientTestCase {

    private VaultContainerHttps<?> vaultTestContainer;
    private SSLContext sslContext;

    @BeforeEach
    public void beforeEach() throws Exception {
        vaultTestContainer = new VaultContainerHttps<>("hashicorp/vault:1.13")
                .withVaultToken("myroot")
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 ttl=30m top_secret=password123",
                        "kv put secret/testing2 ttl=30m dbuser=secretpass jmsuser=jmspass",
                        "kv put secret/my-secret ttl=30m my-value=s3cr3t"
                );
        vaultTestContainer.start();

        sslContext = SslContextTestHelper.createTrustOnly(vaultTestContainer.getHttpsTrustFile());
    }

    @AfterEach
    public void cleanup() {
        if (vaultTestContainer != null) {
            vaultTestContainer.stop();
        }
    }

    /**
     * VaultConnector with SSLContext, test get secret over HTTPS
     */
    @Test
    public void testGetSecretWithHttpClientSslContext() throws VaultException {
        SslConfig sslConfig = new SslConfig().verify(true).build();
        VaultConnector connector = new VaultConnector(
                vaultTestContainer.composeHttpsHostAddress(),
                "myroot",
                null,
                sslConfig,
                true,
                sslContext);
        connector.configure();
        assertEquals("password123", connector.getSecret("secret/testing1", "top_secret"));
    }

    /**
     * VaultConnector with SSLContext, test put secret over HTTPS
     */
    @Test
    public void testPutSecretWithHttpClientSslContext() throws VaultException {
        SslConfig sslConfig = new SslConfig().verify(true).build();
        VaultConnector connector = new VaultConnector(
                vaultTestContainer.composeHttpsHostAddress(),
                "myroot",
                null,
                sslConfig,
                true,
                sslContext);
        connector.configure();
        connector.putSecret("secret/testing1", "top_secret2", "password2");
        assertEquals("password2", connector.getSecret("secret/testing1", "top_secret2"));
    }

    /**
     * VaultConnector with SSLContext, test remove secret over HTTPS
     */
    @Test
    public void testRemoveSecretWithHttpClientSslContext() throws VaultException {
        SslConfig sslConfig = new SslConfig().verify(true).build();
        VaultConnector connector = new VaultConnector(
                vaultTestContainer.composeHttpsHostAddress(),
                "myroot",
                null,
                sslConfig,
                true,
                sslContext);
        connector.configure();
        assertEquals("password123", connector.getSecret("secret/testing1", "top_secret"));
        connector.removeSecret("secret/testing1", "top_secret");
        assertNull(connector.getSecret("secret/testing1", "top_secret"));
    }
}
