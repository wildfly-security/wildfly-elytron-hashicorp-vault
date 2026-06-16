/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.interfaces.ClearPassword;

import io.github.jopenlibs.vault.SslConfig;

public class VaultCredentialSourceTestCase {

    VaultContainer<?> vaultTestContainer;

    @AfterEach
    public void cleanup() {
        if (vaultTestContainer != null) {
            vaultTestContainer.stop();
        }
    }

    @Test
    public void testGetSecretFromVaultService() throws Exception {
        // setup and start test container with vault
        vaultTestContainer = VaultTestUtils.startVaultTestContainer();

        // Start Vault service
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.getHttpHostAddress(), "myroot", "/v1/secret/data/testing2", new SslConfig().verify(true).build(), true);

        // Test credential source with vault service
        VaultCredentialSource credentialSource = new VaultCredentialSource(vaultService, "secret/testing1", "top_secret");
        PasswordCredential credential = credentialSource.getCredential(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null);
        assertEquals("password123", String.valueOf(credential.getPassword(ClearPassword.class).getPassword()));
    }

    @Test
    public void testGetSecretFromVaultServiceReturnNullWithIncorrectPath() throws Exception {
        // setup and start test container with vault
        vaultTestContainer = VaultTestUtils.startVaultTestContainer();

        // Start Vault service
        VaultConnector vaultService = new VaultConnector(vaultTestContainer.getHttpHostAddress(), "myroot", "/v1/secret/data/testing2", new SslConfig().verify(true).build(), true);

        // Test credential source with vault service
        VaultCredentialSource credentialSource = new VaultCredentialSource(vaultService, "secret/testing1", "incorrect");
        PasswordCredential credential = credentialSource.getCredential(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null);
        assertNull(credential);
    }

    @Test
    public void testGetSecretFromVaultServiceFailsWithIncorrectToken() throws Exception {
        // setup and start test container with vault
        vaultTestContainer = VaultTestUtils.startVaultTestContainer();
        // Start Vault service
        VaultConnector vaultConnector = new VaultConnector(vaultTestContainer.getHttpHostAddress(), "incorrect", "/v1/secret/data/testing2", new SslConfig().verify(true).build(), true);

        // Test credential source with vault service
        VaultCredentialSource credentialSource = new VaultCredentialSource(vaultConnector, "secret/testing1", "incorrect");
        assertThrows(IOException.class, () ->  credentialSource.getCredential(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null));
    }
}
