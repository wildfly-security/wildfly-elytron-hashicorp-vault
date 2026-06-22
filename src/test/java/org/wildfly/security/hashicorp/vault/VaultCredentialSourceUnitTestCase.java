/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.interfaces.ClearPassword;

import io.github.jopenlibs.vault.SslConfig;

/**
 * Unit tests for {@link VaultCredentialSource} constructor validation,
 * {@code isCredentialSupported}, and {@code getCredentialAcquireSupport}.
 */
public class VaultCredentialSourceUnitTestCase {

    private VaultConnector dummyConnector() {
        return new VaultConnector("http://dummy", "token", null, new SslConfig(), true);
    }

    // --- Constructor validation ---

    /**
     * Pass {@code null} as the VaultConnector argument.
     * Test passes when {@link IllegalArgumentException} is thrown.
     */
    @Test
    public void testConstructorWithNullConnectorThrows() {
        assertThrows(IllegalArgumentException.class,
                () -> new VaultCredentialSource(null, "secret/path", "key"));
    }

    /**
     * Pass null, empty, or blank string as the secret path argument.
     * Test passes when {@link IllegalArgumentException} is thrown for each invalid value.
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    public void testConstructorWithInvalidPathThrows(String path) {
        assertThrows(IllegalArgumentException.class,
                () -> new VaultCredentialSource(dummyConnector(), path, "key"));
    }

    /**
     * Pass null, empty, or blank string as the secret key argument.
     * Test passes when {@link IllegalArgumentException} is thrown for each invalid value.
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    public void testConstructorWithInvalidKeyThrows(String key) {
        assertThrows(IllegalArgumentException.class,
                () -> new VaultCredentialSource(dummyConnector(), "secret/path", key));
    }

    // --- isCredentialSupported ---

    /**
     * Query support for {@link PasswordCredential} with a {@code null} algorithm.
     * Test passes when the method returns {@code true} (null algorithm means "any").
     */
    @Test
    public void testIsCredentialSupportedPasswordWithNullAlgorithm() throws IOException {
        VaultCredentialSource source = new VaultCredentialSource(dummyConnector(), "secret/path", "key");
        assertTrue(source.isCredentialSupported(PasswordCredential.class, null, null));
    }

    /**
     * Query support for {@link PasswordCredential} with {@code ClearPassword.ALGORITHM_CLEAR}.
     * Test passes when the method returns {@code true}.
     */
    @Test
    public void testIsCredentialSupportedPasswordWithClearAlgorithm() throws IOException {
        VaultCredentialSource source = new VaultCredentialSource(dummyConnector(), "secret/path", "key");
        assertTrue(source.isCredentialSupported(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null));
    }

    /**
     * Query support for {@link PasswordCredential} with an unsupported algorithm name.
     * Test passes when the method returns {@code false}.
     */
    @Test
    public void testIsCredentialSupportedPasswordWithWrongAlgorithm() throws IOException {
        VaultCredentialSource source = new VaultCredentialSource(dummyConnector(), "secret/path", "key");
        assertFalse(source.isCredentialSupported(PasswordCredential.class, "PBKDF2", null));
    }

    /**
     * Query support for a credential type other than {@link PasswordCredential}.
     * Test passes when the method returns {@code false}.
     */
    @Test
    public void testIsCredentialSupportedNonPasswordType() throws IOException {
        VaultCredentialSource source = new VaultCredentialSource(dummyConnector(), "secret/path", "key");
        assertFalse(source.isCredentialSupported(Credential.class, null, null));
    }

    // --- getCredentialAcquireSupport ---

    /**
     * Query acquire support for a supported credential type and algorithm.
     * Test passes when the method returns {@link SupportLevel#SUPPORTED}.
     */
    @Test
    public void testGetCredentialAcquireSupportReturnsSupported() throws IOException {
        VaultCredentialSource source = new VaultCredentialSource(dummyConnector(), "secret/path", "key");
        assertEquals(SupportLevel.SUPPORTED,
                source.getCredentialAcquireSupport(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null));
    }

    /**
     * Query acquire support for an unsupported credential type.
     * Test passes when the method returns {@link SupportLevel#UNSUPPORTED}.
     */
    @Test
    public void testGetCredentialAcquireSupportReturnsUnsupported() throws IOException {
        VaultCredentialSource source = new VaultCredentialSource(dummyConnector(), "secret/path", "key");
        assertEquals(SupportLevel.UNSUPPORTED,
                source.getCredentialAcquireSupport(Credential.class, null, null));
    }

    // --- getCredential with unsupported type ---

    /**
     * Request a credential of a type other than {@link PasswordCredential}.
     * Test passes when the method returns {@code null} without attempting a vault call.
     */
    @Test
    public void testGetCredentialWithNonPasswordTypeReturnsNull() throws IOException {
        VaultCredentialSource source = new VaultCredentialSource(dummyConnector(), "secret/path", "key");
        Credential result = source.getCredential(Credential.class, null, null);
        assertNull(result);
    }
}
