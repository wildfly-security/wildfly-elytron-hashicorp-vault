/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.wildfly.security.credential.store.CredentialStoreException;

import io.github.jopenlibs.vault.SslConfig;

/**
 * Unit tests for input validation in {@link VaultConnector} with the new alias-based API.
 * These tests verify null/empty guard clauses without needing a running Vault instance,
 * since validation throws before any Vault API call is made.
 *
 * NOTE: With the new alias-based API, validation happens at the VaultAlias parsing level,
 * so these tests now validate alias format rather than individual path/key parameters.
 */
public class VaultConnectorValidationTestCase {

    private VaultConnector connector;

    @BeforeEach
    public void setup() {
        connector = new VaultConnector("http://dummy", "token", null, new SslConfig(), true);
    }

    // --- Alias validation ---

    /**
     * Test that null alias throws CredentialStoreException.
     */
    @Test
    public void testNullAlias() {
        assertThrows(CredentialStoreException.class, () -> connector.getSecretData(null));
        assertThrows(CredentialStoreException.class, () -> connector.putSecretData(null, "value"));
        assertThrows(CredentialStoreException.class, () -> connector.removeSecretData(null));
    }

    /**
     * Test that null value for putSecretData throws CredentialStoreException.
     */
    @Test
    public void testPutSecretNullValue() throws Exception {
        VaultAlias alias = VaultAlias.parse("#test?key");
        assertThrows(CredentialStoreException.class, () -> connector.putSecretData(alias, null));
    }

    /**
     * Test that invalid alias formats throw CredentialStoreException during parsing.
     * These tests verify VaultAlias.parse() validation.
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t", "\n"})
    public void testInvalidAliasFormat(String alias) {
        assertThrows(CredentialStoreException.class, () -> VaultAlias.parse(alias));
    }

    /**
     * Test that alias missing required delimiter (?) throws CredentialStoreException.
     */
    @Test
    public void testAliasMissingKeyDelimiter() {
        assertThrows(CredentialStoreException.class, () -> VaultAlias.parse("#test"));
        assertThrows(CredentialStoreException.class, () -> VaultAlias.parse("#test/path"));
    }

    /**
     * Test that alias with empty secret path throws CredentialStoreException.
     */
    @Test
    public void testAliasEmptySecretPath() {
        assertThrows(CredentialStoreException.class, () -> VaultAlias.parse("#?key"));
        assertThrows(CredentialStoreException.class, () -> VaultAlias.parse("@mount#?key"));
    }

    /**
     * Test that alias with empty key path throws CredentialStoreException.
     */
    @Test
    public void testAliasEmptyKeyPath() {
        assertThrows(CredentialStoreException.class, () -> VaultAlias.parse("#test?"));
        assertThrows(CredentialStoreException.class, () -> VaultAlias.parse("#test/path?"));
    }

    // NOTE: Tests for getKeysForPath() and listAllItemsAtPath() have been removed
    // as these methods are no longer part of the VaultConnector API.
}
