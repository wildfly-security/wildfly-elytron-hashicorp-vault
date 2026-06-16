/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault.loginstrategy;

import org.wildfly.security.hashicorp.vault.JwtConfig;

import io.github.jopenlibs.vault.Vault;

/**
 * Current login context for the vault.
 */
public class LoginContext {

    private final String token;
    private final JwtConfig jwtConfig;
    private final Vault vault;

    public LoginContext(String token, JwtConfig jwtConfig, Vault vault) {
        this.token = token;
        this.jwtConfig = jwtConfig;
        this.vault = vault;
    }

    public String getToken() {
        return token;
    }

    public JwtConfig getJwtConfig() {
        return jwtConfig;
    }

    public Vault getVault() {
        return vault;
    }
}
