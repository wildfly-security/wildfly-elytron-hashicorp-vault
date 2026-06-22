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

/**
 * Unit tests for {@link JwtConfig} constructor validation and getters.
 */
public class JwtConfigTestCase {

    /**
     * Construct a JwtConfig with all valid non-empty arguments.
     * Test passes when all three getters return the values provided to the constructor.
     */
    @Test
    public void testValidConstruction() {
        JwtConfig config = new JwtConfig("myJwt", "myRole", "myProvider");
        assertEquals("myJwt", config.getJwt());
        assertEquals("myRole", config.getJwtRole());
        assertEquals("myProvider", config.getJwtProvider());
    }

    /**
     * Pass null, empty, or blank string as the jwt argument.
     * Test passes when {@link IllegalArgumentException} is thrown for each invalid value.
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    public void testInvalidJwtThrows(String jwt) {
        assertThrows(IllegalArgumentException.class, () -> new JwtConfig(jwt, "role", "provider"));
    }

    /**
     * Pass null, empty, or blank string as the jwtRole argument.
     * Test passes when {@link IllegalArgumentException} is thrown for each invalid value.
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    public void testInvalidRoleThrows(String role) {
        assertThrows(IllegalArgumentException.class, () -> new JwtConfig("jwt", role, "provider"));
    }

    /**
     * Pass null, empty, or blank string as the jwtProvider argument.
     * Test passes when {@link IllegalArgumentException} is thrown for each invalid value.
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    public void testInvalidProviderThrows(String provider) {
        assertThrows(IllegalArgumentException.class, () -> new JwtConfig("jwt", "role", provider));
    }
}
