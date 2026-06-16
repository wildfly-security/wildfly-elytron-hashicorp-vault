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

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.VaultException;

/**
 * Unit tests for input validation in {@link VaultConnector}.
 * These tests verify null/empty guard clauses without needing a running Vault instance,
 * since validation throws before any Vault API call is made.
 */
public class VaultConnectorValidationTestCase {

    private VaultConnector connector;

    @BeforeEach
    public void setup() {
        connector = new VaultConnector("http://dummy", "token", null, new SslConfig(), true);
    }

    // --- getSecret validation ---

    /**
     * Call {@code getSecret} with null, empty, or blank path values.
     * Test passes when {@link VaultException} is thrown before any vault interaction.
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    public void testGetSecretInvalidPath(String path) {
        assertThrows(VaultException.class, () -> connector.getSecret(path, "key"));
    }

    /**
     * Call {@code getSecret} with null, empty, or blank key values.
     * Test passes when {@link VaultException} is thrown before any vault interaction.
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    public void testGetSecretInvalidKey(String key) {
        assertThrows(VaultException.class, () -> connector.getSecret("secret/path", key));
    }

    // --- putSecret validation ---

    /**
     * Call {@code putSecret} with null, empty, or blank path values.
     * Test passes when {@link VaultException} is thrown before any vault interaction.
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    public void testPutSecretInvalidPath(String path) {
        assertThrows(VaultException.class, () -> connector.putSecret(path, "key", "value"));
    }

    /**
     * Call {@code putSecret} with null, empty, or blank key values.
     * Test passes when {@link VaultException} is thrown before any vault interaction.
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    public void testPutSecretInvalidKey(String key) {
        assertThrows(VaultException.class, () -> connector.putSecret("secret/path", key, "value"));
    }

    /**
     * Call {@code putSecret} with a {@code null} value.
     * Test passes when {@link VaultException} is thrown before any vault interaction.
     */
    @Test
    public void testPutSecretNullValue() {
        assertThrows(VaultException.class, () -> connector.putSecret("secret/path", "key", null));
    }

    // --- removeSecret validation ---

    /**
     * Call {@code removeSecret} with null, empty, or blank path values.
     * Test passes when {@link VaultException} is thrown before any vault interaction.
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    public void testRemoveSecretInvalidPath(String path) {
        assertThrows(VaultException.class, () -> connector.removeSecret(path, "key"));
    }

    /**
     * Call {@code removeSecret} with null, empty, or blank key values.
     * Test passes when {@link VaultException} is thrown before any vault interaction.
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    public void testRemoveSecretInvalidKey(String key) {
        assertThrows(VaultException.class, () -> connector.removeSecret("secret/path", key));
    }

    // --- listAllItemsAtPath validation ---

    /**
     * Call {@code listAllItemsAtPath} with null, empty, or blank path values.
     * Test passes when {@link VaultException} is thrown before any vault interaction.
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    public void testListAllItemsAtPathInvalidPath(String path) {
        assertThrows(VaultException.class, () -> connector.listAllItemsAtPath(path));
    }
}
