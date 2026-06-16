/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.security.Security;

import org.junit.jupiter.api.Test;
import org.wildfly.security.credential.store.CredentialStore;

/**
 * Unit tests for {@link HashicorpVaultCredentialStoreProvider}.
 */
public class HashicorpVaultCredentialStoreProviderTestCase {

    /**
     * Call {@code getInstance()} twice and compare the returned references.
     * Test passes when both calls return the same non-null instance.
     */
    @Test
    public void testGetInstanceReturnsSingleton() {
        HashicorpVaultCredentialStoreProvider p1 = HashicorpVaultCredentialStoreProvider.getInstance();
        HashicorpVaultCredentialStoreProvider p2 = HashicorpVaultCredentialStoreProvider.getInstance();
        assertNotNull(p1);
        assertSame(p1, p2);
    }

    /**
     * Verify the provider advertises the expected name.
     * Test passes when {@code getName()} returns {@code "WildFlyElytronHashicorpVaultProvider"}.
     */
    @Test
    public void testProviderName() {
        HashicorpVaultCredentialStoreProvider provider = HashicorpVaultCredentialStoreProvider.getInstance();
        assertEquals("WildFlyElytronHashicorpVaultProvider", provider.getName());
    }

    /**
     * Verify the provider registers a {@code CredentialStore} service for {@code "HashicorpVaultCredentialStore"}.
     * Test passes when {@code getService()} returns a non-null service descriptor.
     */
    @Test
    public void testProviderRegistersCredentialStoreService() {
        HashicorpVaultCredentialStoreProvider provider = HashicorpVaultCredentialStoreProvider.getInstance();
        assertNotNull(provider.getService("CredentialStore", "HashicorpVaultCredentialStore"));
    }

    /**
     * Verify that the package-private {@code HashicorpVaultCredentialStore} class can be instantiated
     * via the Security Provider framework using reflection.
     * Test passes when {@code CredentialStore.getInstance()} successfully returns a non-null instance.
     */
    @Test
    public void testCredentialStoreCanBeInstantiatedViaSecurityProvider() throws Exception {
        HashicorpVaultCredentialStoreProvider provider = HashicorpVaultCredentialStoreProvider.getInstance();
        Security.addProvider(provider);
        try {
            CredentialStore credentialStore = CredentialStore.getInstance("HashicorpVaultCredentialStore", provider);
            assertNotNull(credentialStore);
        } finally {
            Security.removeProvider(provider.getName());
        }
    }
}
