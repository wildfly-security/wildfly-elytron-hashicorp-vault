/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.wildfly.security.hashicorp.vault.loginstrategy.JwtLoginStrategy;
import org.wildfly.security.hashicorp.vault.loginstrategy.LoginContext;
import org.wildfly.security.hashicorp.vault.loginstrategy.TokenLoginStrategy;

import io.github.jopenlibs.vault.VaultException;

/**
 * Unit tests for {@link TokenLoginStrategy} and {@link JwtLoginStrategy}.
 */
public class LoginStrategyUnitTestCase {

    /**
     * Invoke {@code tryLogin} with a context containing a valid non-empty token.
     * Test passes when the strategy returns the exact token string.
     */
    @Test
    public void testTokenLoginWithValidToken() throws VaultException {
        LoginContext context = new LoginContext("validToken", null, null);
        TokenLoginStrategy strategy = new TokenLoginStrategy();
        assertEquals("validToken", strategy.tryLogin(context));
    }

    /**
     * Invoke {@code tryLogin} with null, empty, or blank tokens.
     * Test passes when {@link VaultException} is thrown for each invalid token value.
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t", "\n"})
    public void testTokenLoginWithInvalidToken(String token) {
        LoginContext context = new LoginContext(token, null, null);
        TokenLoginStrategy strategy = new TokenLoginStrategy();
        assertThrows(VaultException.class, () -> strategy.tryLogin(context));
    }

    /**
     * Invoke {@code tryLogin} with a context that has no JWT configuration.
     * Test passes when {@link VaultException} is thrown indicating missing JWT config.
     */
    @Test
    public void testJwtLoginWithNullConfigThrows() {
        LoginContext context = new LoginContext(null, null, null);
        JwtLoginStrategy strategy = new JwtLoginStrategy();
        assertThrows(VaultException.class, () -> strategy.tryLogin(context));
    }
}
