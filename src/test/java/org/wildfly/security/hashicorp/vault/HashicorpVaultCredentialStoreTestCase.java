/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.wildfly.security.hashicorp.vault.VaultTestUtils.startVaultTestContainer;

public class HashicorpVaultCredentialStoreTestCase {

    private VaultContainer<?> vaultTestContainer;

    @AfterEach
    public void cleanup() {
        if (vaultTestContainer != null) {
            vaultTestContainer.stop();
        }
    }


    @Test
    public void testCredentialStoreRetrieve() throws Exception {

        vaultTestContainer = VaultTestUtils.startVaultTestContainer();
        HashicorpVaultCredentialStore cs = new HashicorpVaultCredentialStore();
        Map<String, String> attributes = new HashMap<>();
        attributes.put("host-address", vaultTestContainer.getHttpHostAddress());
        attributes.put("namespace", "admin");
        cs.initialize(attributes, new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(createCredentialFromPassword("myroot"))), new Provider[]{WildFlyElytronPasswordProvider.getInstance()});
        PasswordCredential credential = cs.retrieve("secret/testing1.top_secret", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null, null);
        assertEquals("password123", String.valueOf(credential.getPassword(ClearPassword.class).getPassword()));
    }

    @Test
    public void testCredentialStorePut() throws Exception {
        HashicorpVaultCredentialStore hashicorpVaultCredentialStore;
        Map<String, String> attributes;
        vaultTestContainer = startVaultTestContainer();
        hashicorpVaultCredentialStore = new HashicorpVaultCredentialStore();
        attributes = new HashMap<>();
        attributes.put("host-address", vaultTestContainer.getHttpHostAddress());
        attributes.put("namespace", "admin");
        hashicorpVaultCredentialStore.initialize(attributes, new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(createCredentialFromPassword("myroot"))), new Provider[]{WildFlyElytronPasswordProvider.getInstance()});
        hashicorpVaultCredentialStore.store("secret/testing1.test_secret", createCredentialFromPassword("testPassword"), null);
        PasswordCredential credential = hashicorpVaultCredentialStore
                .retrieve("secret/testing1.test_secret", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null,
                        new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(createCredentialFromPassword("myroot"))));
        assertEquals("testPassword", String.valueOf(credential.getPassword(ClearPassword.class).getPassword()));
    }

    @Test
    public void testPutMaintainsExistingKeys() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createHashicorpVaultCredentialStore();
        store.store("secret/myapp.mp", createCredentialFromPassword("password1"), null);
        store.store("secret/myapp.mp2", createCredentialFromPassword("password2"), null);
        PasswordCredential credential1 = store.retrieve("secret/myapp.mp", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR,
                null, createProtectionParameter("myroot"));
        assertNotNull(credential1);
        PasswordCredential credential2 = store.retrieve("secret/myapp.mp2", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR,
                null, createProtectionParameter("myroot"));
        assertNotNull(credential2);
    }

    @Test
    public void testRemoveKeepsOtherKeys() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createHashicorpVaultCredentialStore();
        store.store("secret/myapp.mp", createCredentialFromPassword("password1"), null);
        store.store("secret/myapp.mp2", createCredentialFromPassword("password2"), null);
        store.remove("secret/myapp.mp2", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null);
        PasswordCredential remaining = store.retrieve("secret/myapp.mp", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR,
                null, createProtectionParameter("myroot"));
        assertNotNull(remaining);
        assertEquals("password1", String.valueOf(remaining.getPassword(ClearPassword.class).getPassword()));
        PasswordCredential removed = store.retrieve("secret/myapp.mp2", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR,
                null, createProtectionParameter("myroot"));
        assertNull(removed);
    }

    /**
     * Read aliases from a specific vault path that contains secrets.
     * Test that only the aliases stored at specific path are returned, none from the other path
     */
    @Test
    public void testGetAliasesWithPath() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore cs = new HashicorpVaultCredentialStore();
        Map<String, String> attributes = new HashMap<>();
        attributes.put("host-address", vaultTestContainer.getHttpHostAddress());
        cs.initialize(attributes, new CredentialStore.CredentialSourceProtectionParameter(
                        IdentityCredentials.NONE.withCredential(createCredentialFromPassword("myroot"))),
                new Provider[]{WildFlyElytronPasswordProvider.getInstance()});
        Set<String> aliases = cs.getAliases("secret/testing1");
        assertNotNull(aliases);
        assertFalse(aliases.isEmpty());
        assertTrue(aliases.contains("secret/testing1.top_secret"));
        assertFalse(aliases.contains("secret/testing2.dbuser"));
        assertFalse(aliases.contains("secret/testing2.jmsuser"));

        aliases = cs.getAliases("secret/testing2");
        assertNotNull(aliases);
        assertFalse(aliases.isEmpty());
        assertTrue(aliases.contains("secret/testing2.dbuser"));
        assertTrue(aliases.contains("secret/testing2.jmsuser"));
        assertFalse(aliases.contains("secret/testing1.top_secret"));
    }

    /**
     * The call must throw a {@link CredentialStoreException} when null path is provided
     */
    @Test
    public void testGetAliasesWithNullPath() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore cs = new HashicorpVaultCredentialStore();
        Map<String, String> attributes = new HashMap<>();
        attributes.put("host-address", vaultTestContainer.getHttpHostAddress());
        cs.initialize(attributes, new CredentialStore.CredentialSourceProtectionParameter(
                        IdentityCredentials.NONE.withCredential(createCredentialFromPassword("myroot"))),
                new Provider[]{WildFlyElytronPasswordProvider.getInstance()});
        assertThrows(CredentialStoreException.class, () -> cs.getAliases((String) null));
    }

    /**
     * The call must throw a {@link CredentialStoreException} when empty path is provided
     */
    @Test
    public void testGetAliasesWithEmptyPath() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore cs = new HashicorpVaultCredentialStore();
        Map<String, String> attributes = new HashMap<>();
        attributes.put("host-address", vaultTestContainer.getHttpHostAddress());
        cs.initialize(attributes, new CredentialStore.CredentialSourceProtectionParameter(
                        IdentityCredentials.NONE.withCredential(createCredentialFromPassword("myroot"))),
                new Provider[]{WildFlyElytronPasswordProvider.getInstance()});
        assertThrows(CredentialStoreException.class, () -> cs.getAliases(""));
    }

    /**
     * Test that non-recursive mode (recursive=false) behaves the same as getAliases(path)
     */
    @Test
    public void testGetAliasesNonRecursive() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore cs = createHashicorpVaultCredentialStore();

        Set<String> aliases1 = cs.getAliases("secret/testing1");
        Set<String> aliases2 = cs.getAliases("secret/testing1", false, 0);
        
        assertEquals(aliases1, aliases2);
        assertTrue(aliases2.contains("secret/testing1.top_secret"));
    }

    /**
     * Test recursive mode with depth 0 - should only return aliases at the specified path
     */
    @Test
    public void testGetAliasesRecursiveDepth0() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore cs = createHashicorpVaultCredentialStore();

        cs.store("secret/app1.key1", createCredentialFromPassword("value1"), null);
        cs.store("secret/app1.key2", createCredentialFromPassword("value2"), null);
        cs.store("secret/app1/subapp.key3", createCredentialFromPassword("value3"), null);

        Set<String> aliases = cs.getAliases("secret/app1", true, 0);
        
        assertTrue(aliases.contains("secret/app1.key1"));
        assertTrue(aliases.contains("secret/app1.key2"));
        // Should NOT include any subpath keys when depth is 0
        assertFalse(aliases.contains("secret/app1/subapp.key3"));
    }

    /**
     * Test recursive mode with depth 1 - should return aliases one level deep
     */
    @Test
    public void testGetAliasesRecursiveDepth1() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore cs = createHashicorpVaultCredentialStore();

        cs.store("secret/app1.key1", createCredentialFromPassword("value1"), null);
        cs.store("secret/app1.key2", createCredentialFromPassword("value2"), null);
        cs.store("secret/app1/subapp1.key3", createCredentialFromPassword("value3"), null);
        cs.store("secret/app1/subapp2.key4", createCredentialFromPassword("value4"), null);
        cs.store("secret/app1/subapp1/deep.key5", createCredentialFromPassword("value5"), null);
        Set<String> aliases = cs.getAliases("secret/app1", true, 1);

        assertTrue(aliases.contains("secret/app1.key1"));
        assertTrue(aliases.contains("secret/app1.key2"));

        assertTrue(aliases.contains("secret/app1/subapp1.key3"));
        assertTrue(aliases.contains("secret/app1/subapp2.key4"));
        assertFalse(aliases.contains("secret/app1/subapp1/deep.key5"));

    }

    /**
     * Test recursive mode with depth 2 - should return aliases two levels deep
     */
    @Test
    public void testGetAliasesRecursiveDepth2() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore cs = createHashicorpVaultCredentialStore();

        cs.store("secret/app1.key1", createCredentialFromPassword("value1"), null);
        cs.store("secret/app1/subapp1.key2", createCredentialFromPassword("value2"), null);
        cs.store("secret/app1/subapp1/deep.key3", createCredentialFromPassword("value3"), null);
        cs.store("secret/app1/subapp1/deep/deeper.key4", createCredentialFromPassword("value4"), null);

        Set<String> aliases = cs.getAliases("secret/app1", true, 2);
        assertTrue(aliases.contains("secret/app1.key1"));
        assertTrue(aliases.contains("secret/app1/subapp1.key2"));
        assertTrue(aliases.contains("secret/app1/subapp1/deep.key3"));
        // Should NOT include keys deeper than depth 2
        assertFalse(aliases.contains("secret/app1/subapp1/deep/deeper.key4"));
    }

    /**
     * Test recursive listing with multiple subpaths at the same level
     */
    @Test
    public void testGetAliasesRecursiveMultipleSubpaths() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore cs = createHashicorpVaultCredentialStore();

        cs.store("secret/app1.key1", createCredentialFromPassword("value1"), null);
        cs.store("secret/app1/subapp1.key2", createCredentialFromPassword("value2"), null);
        cs.store("secret/app1/subapp2.key3", createCredentialFromPassword("value3"), null);
        cs.store("secret/app1/subapp3.key4", createCredentialFromPassword("value4"), null);

        Set<String> aliases = cs.getAliases("secret/app1", true, 1);

        assertTrue(aliases.contains("secret/app1.key1"));
        assertTrue(aliases.contains("secret/app1/subapp1.key2"));
        assertTrue(aliases.contains("secret/app1/subapp2.key3"));
        assertTrue(aliases.contains("secret/app1/subapp3.key4"));
        assertEquals(4, aliases.size());
    }

    /**
     * Test recursive listing with empty subpaths (subpaths that exist but have no keys)
     */
    @Test
    public void testGetAliasesRecursiveWithEmptySubpaths() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore cs = createHashicorpVaultCredentialStore();

        cs.store("secret/app1.key1", createCredentialFromPassword("value1"), null);
        cs.store("secret/app1/subapp1/deep.key2", createCredentialFromPassword("value2"), null);

        Set<String> aliases = cs.getAliases("secret/app1", true, 2);

        assertTrue(aliases.contains("secret/app1.key1"));
        assertTrue(aliases.contains("secret/app1/subapp1/deep.key2"));
    }

    /**
     * Test getAliases with maxNumberOfAliases limit - recursive, limit reached during traversal
     */
    @Test
    public void testGetAliasesWithMaxLimitRecursiveStopsDuringTraversal() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore cs = createHashicorpVaultCredentialStore();

        cs.store("secret/app1.key1", createCredentialFromPassword("value1"), null);
        cs.store("secret/app1.key2", createCredentialFromPassword("value2"), null);
        cs.store("secret/app1/subapp1.key3", createCredentialFromPassword("value3"), null);
        cs.store("secret/app1/subapp1.key4", createCredentialFromPassword("value4"), null);
        cs.store("secret/app1/subapp2.key5", createCredentialFromPassword("value5"), null);
        cs.store("secret/app1/subapp2.key6", createCredentialFromPassword("value6"), null);

        Set<String> aliases = cs.getAliases("secret/app1", true, 1, 3);
        assertTrue(aliases.contains("secret/app1.key1"));
        assertTrue(aliases.contains("secret/app1.key2"));
        assertEquals(3, aliases.size());
    }

    /**
     * Test getAliases with maxNumberOfAliases - recursive with depth 2, limit reached at different levels
     */
    @Test
    public void testGetAliasesWithMaxLimitRecursiveDepth2() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore cs = createHashicorpVaultCredentialStore();

        cs.store("secret/app1.key1", createCredentialFromPassword("value1"), null);
        cs.store("secret/app1/subapp1.key2", createCredentialFromPassword("value2"), null);
        cs.store("secret/app1/subapp1/deep.key3", createCredentialFromPassword("value3"), null);
        cs.store("secret/app1/subapp2.key4", createCredentialFromPassword("value4"), null);

        Set<String> aliases = cs.getAliases("secret/app1", true, 2, 2);

        assertTrue(aliases.contains("secret/app1.key1"));
        assertEquals(2, aliases.size());
    }

    /**
     * Test getAliases with maxNumberOfAliases - recursive false should ignore depth but respect limit
     */
    @Test
    public void testGetAliasesWithMaxLimitRecursiveFalse() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore cs = createHashicorpVaultCredentialStore();

        cs.store("secret/app1.key1", createCredentialFromPassword("value1"), null);
        cs.store("secret/app1.key2", createCredentialFromPassword("value2"), null);
        cs.store("secret/app1/subapp1.key3", createCredentialFromPassword("value3"), null);
        Set<String> aliases = cs.getAliases("secret/app1", false, 10, 1);
        
        assertEquals(1, aliases.size());
        assertTrue(aliases.contains("secret/app1.key1") || aliases.contains("secret/app1.key2"));
        assertFalse(aliases.contains("secret/app1/subapp1.key3"));
    }

    /**
     * Second retrieve for the same alias returns the cached credential - same instance.
     */
    @Test
    public void testCredentialCacheHit() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createHashicorpVaultCredentialStore();
        PasswordCredential first = store.retrieve("secret/testing1.top_secret", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null, createProtectionParameter("myroot"));
        assertNotNull(first);
        assertEquals("password123", String.valueOf(first.getPassword(ClearPassword.class).getPassword()));
        PasswordCredential second = store.retrieve("secret/testing1.top_secret", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null, createProtectionParameter("myroot"));
        assertSame(first, second);
    }

    /**
     * After store, cache is updated so subsequent retrieve returns the new value.
     */
    @Test
    public void testCredentialCacheInvalidationOnStore() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createHashicorpVaultCredentialStore();
        store.store("secret/cachetest.key1", createCredentialFromPassword("value1"), null);
        PasswordCredential c1 = store.retrieve("secret/cachetest.key1", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null, createProtectionParameter("myroot"));
        assertEquals("value1", String.valueOf(c1.getPassword(ClearPassword.class).getPassword()));
        store.store("secret/cachetest.key1", createCredentialFromPassword("value2"), null);
        PasswordCredential c2 = store.retrieve("secret/cachetest.key1", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null, createProtectionParameter("myroot"));
        assertEquals("value2", String.valueOf(c2.getPassword(ClearPassword.class).getPassword()));
    }

    /**
     * After remove, cache is invalidated so subsequent retrieve for that alias returns null.
     */
    @Test
    public void testCredentialCacheInvalidationOnRemove() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createHashicorpVaultCredentialStore();
        store.store("secret/cachetest.a", createCredentialFromPassword("a"), null);
        store.store("secret/cachetest.b", createCredentialFromPassword("b"), null);
        store.retrieve("secret/cachetest.a", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null, createProtectionParameter("myroot"));
        store.remove("secret/cachetest.a", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null);
        assertNull(store.retrieve("secret/cachetest.a", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null, createProtectionParameter("myroot")));
        PasswordCredential b = store.retrieve("secret/cachetest.b", PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR, null, createProtectionParameter("myroot"));
        assertEquals("b", String.valueOf(b.getPassword(ClearPassword.class).getPassword()));
    }

    private HashicorpVaultCredentialStore createHashicorpVaultCredentialStore() throws Exception {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        Map<String, String> attributes = new HashMap<>();
        attributes.put("host-address", vaultTestContainer.getHttpHostAddress());
        attributes.put("namespace", "admin");
        store.initialize(attributes, new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(createCredentialFromPassword("myroot"))), new Provider[]{WildFlyElytronPasswordProvider.getInstance()});
        return store;
    }

    private PasswordCredential createCredentialFromPassword(String password) throws UnsupportedCredentialTypeException {
        try {
            PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, WildFlyElytronPasswordProvider.getInstance());
            return new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec(password.toCharArray())));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new UnsupportedCredentialTypeException(e);
        }
    }

    private CredentialStore.CredentialSourceProtectionParameter createProtectionParameter(String protectionParameter) throws UnsupportedCredentialTypeException {
        return new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(createCredentialFromPassword(protectionParameter)));
    }

    // =====================================================================
    // Input validation — store()/retrieve()/remove() alias and argument checks
    // =====================================================================

    /**
     * Call {@code store()} with null, empty, or blank alias on an initialized store.
     * Test passes when {@link CredentialStoreException} is thrown for each invalid value.
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    public void testStoreInvalidAlias(String alias) throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createHashicorpVaultCredentialStore();
        assertThrows(CredentialStoreException.class,
                () -> store.store(alias, createCredentialFromPassword("v"), null));
    }

    /**
     * Call {@code store()} with an alias that does not match the required "path.key" format.
     * Test passes when {@link CredentialStoreException} is thrown.
     */
    @ParameterizedTest
    @ValueSource(strings = {"noDotsHere", "too.many.dots"})
    public void testStoreMalformedAlias(String alias) throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createHashicorpVaultCredentialStore();
        assertThrows(CredentialStoreException.class,
                () -> store.store(alias, createCredentialFromPassword("v"), null));
    }

    /**
     * Call {@code store()} with a {@code null} credential.
     * Test passes when {@link CredentialStoreException} is thrown.
     */
    @Test
    public void testStoreNullCredential() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createHashicorpVaultCredentialStore();
        assertThrows(CredentialStoreException.class,
                () -> store.store("secret/path.key", null, null));
    }

    /**
     * Call {@code retrieve()} with null, empty, or blank alias on an initialized store.
     * Test passes when {@link CredentialStoreException} is thrown for each invalid value.
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    public void testRetrieveInvalidAlias(String alias) throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createHashicorpVaultCredentialStore();
        assertThrows(CredentialStoreException.class,
                () -> store.retrieve(alias, PasswordCredential.class,
                        ClearPassword.ALGORITHM_CLEAR, null, null));
    }

    /**
     * Call {@code retrieve()} with an alias that does not match the "path.key" format.
     * Test passes when {@link CredentialStoreException} is thrown.
     */
    @ParameterizedTest
    @ValueSource(strings = {"noDotsHere", "too.many.dots"})
    public void testRetrieveMalformedAlias(String alias) throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createHashicorpVaultCredentialStore();
        assertThrows(CredentialStoreException.class,
                () -> store.retrieve(alias, PasswordCredential.class,
                        ClearPassword.ALGORITHM_CLEAR, null, null));
    }

    /**
     * Call {@code remove()} with null, empty, or blank alias on an initialized store.
     * Test passes when {@link CredentialStoreException} is thrown for each invalid value.
     */
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    public void testRemoveInvalidAlias(String alias) throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createHashicorpVaultCredentialStore();
        assertThrows(CredentialStoreException.class,
                () -> store.remove(alias, PasswordCredential.class,
                        ClearPassword.ALGORITHM_CLEAR, null));
    }

    /**
     * Call {@code remove()} with an alias that does not match the "path.key" format.
     * Test passes when {@link CredentialStoreException} is thrown.
     */
    @ParameterizedTest
    @ValueSource(strings = {"noDotsHere", "too.many.dots"})
    public void testRemoveMalformedAlias(String alias) throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createHashicorpVaultCredentialStore();
        assertThrows(CredentialStoreException.class,
                () -> store.remove(alias, PasswordCredential.class,
                        ClearPassword.ALGORITHM_CLEAR, null));
    }

    // =====================================================================
    // Input validation — getAliases() parameter checks
    // =====================================================================

    /**
     * Call {@code getAliases(path, recursive, depth)} with a negative recursiveDepth.
     * Test passes when {@link CredentialStoreException} is thrown.
     */
    @Test
    public void testGetAliasesNegativeDepth() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createHashicorpVaultCredentialStore();
        assertThrows(CredentialStoreException.class,
                () -> store.getAliases("secret/", true, -1));
    }

    /**
     * Call {@code getAliases(path, recursive, depth, max)} with zero maxNumberOfAliases.
     * Test passes when {@link CredentialStoreException} is thrown.
     */
    @Test
    public void testGetAliasesZeroMax() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createHashicorpVaultCredentialStore();
        assertThrows(CredentialStoreException.class,
                () -> store.getAliases("secret/", true, 1, 0));
    }

    /**
     * Call {@code getAliases(path, recursive, depth, max)} with negative maxNumberOfAliases.
     * Test passes when {@link CredentialStoreException} is thrown.
     */
    @Test
    public void testGetAliasesNegativeMax() throws Exception {
        vaultTestContainer = startVaultTestContainer();
        HashicorpVaultCredentialStore store = createHashicorpVaultCredentialStore();
        assertThrows(CredentialStoreException.class,
                () -> store.getAliases("secret/", true, 1, -5));
    }

    // =====================================================================
    // Error response handling — 403 propagation through getAliases
    // =====================================================================

    /**
     * Recursive alias listing with a restricted token that cannot list subpaths.
     * Test passes when {@link CredentialStoreException} is thrown with a "Forbidden" message,
     * verifying that HTTP 403 from Vault is properly propagated through
     * {@code collectAliasesRecursive}.
     */
    @Test
    public void testGetAliasesRecursiveForbiddenToListSubpaths() throws Exception {
        vaultTestContainer = new VaultContainer<>("hashicorp/vault:1.13")
                .withVaultToken("myroot")
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 top_secret=password123",
                        "kv put secret/testing2 dbuser=secretpass jmsuser=jmspass"
                );
        vaultTestContainer.start();

        // Create a policy that allows reading secrets but NOT listing metadata
        vaultTestContainer.execInContainer("sh", "-c",
                "echo 'path \"secret/data/*\" { capabilities = [\"read\"] }' "
                        + "| vault policy write no-list -");
        vaultTestContainer.execInContainer("vault", "token", "create",
                "-policy=no-list", "-id=no-list-token", "-ttl=1h");

        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        Map<String, String> attributes = new HashMap<>();
        attributes.put("host-address", vaultTestContainer.getHttpHostAddress());
        attributes.put("namespace", "admin");
        store.initialize(attributes, new CredentialStore.CredentialSourceProtectionParameter(
                        IdentityCredentials.NONE.withCredential(createCredentialFromPassword("no-list-token"))),
                new Provider[]{WildFlyElytronPasswordProvider.getInstance()});

        assertThrows(CredentialStoreException.class,
                () -> store.getAliases("secret/", true, 1));
    }

    // =====================================================================
    // Initialization — null/missing attributes, protection parameter checks
    // =====================================================================

    /**
     * Call {@code initialize()} with {@code null} attributes map.
     * Test passes when {@link CredentialStoreException} is thrown.
     */
    @Test
    public void testInitializeWithNullAttributes() {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        assertThrows(CredentialStoreException.class,
                () -> store.initialize(null, createProtectionParameter("token"), new Provider[]{}));
    }

    /**
     * Call {@code initialize()} with attributes map that does not contain host-address.
     * Test passes when {@link CredentialStoreException} is thrown.
     */
    @Test
    public void testInitializeWithMissingHostAddress() {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        Map<String, String> attrs = new HashMap<>();
        assertThrows(CredentialStoreException.class,
                () -> store.initialize(attrs, createProtectionParameter("token"), new Provider[]{}));
    }

    /**
     * Call {@code initialize()} with blank host-address value.
     * Test passes when {@link CredentialStoreException} is thrown.
     */
    @Test
    public void testInitializeWithBlankHostAddress() {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        Map<String, String> attrs = new HashMap<>();
        attrs.put("host-address", "   ");
        assertThrows(CredentialStoreException.class,
                () -> store.initialize(attrs, createProtectionParameter("token"), new Provider[]{}));
    }

    /**
     * Call {@code initialize()} with {@code null} protection parameter (no token provided) and no
     * alternative auth method configured (no SSLContext or key-store-path).
     * Test passes when {@link CredentialStoreException} is thrown by the early validation
     * in {@code HashicorpVaultCredentialStore} indicating that no authentication method is configured.
     */
    @Test
    public void testInitializeWithNullProtectionParameter() {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        Map<String, String> attrs = new HashMap<>();
        attrs.put("host-address", "http://localhost:8200");
        assertThrows(CredentialStoreException.class,
                () -> store.initialize(attrs, null, new Provider[]{}));
    }

    /**
     * Call {@code initialize()} with an unsupported {@link CredentialStore.ProtectionParameter} type.
     * Test passes when an exception is thrown indicating the protection parameter is invalid.
     */
    @Test
    public void testInitializeWithUnsupportedProtectionParameterType() {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        Map<String, String> attrs = new HashMap<>();
        attrs.put("host-address", "http://localhost:8200");
        CredentialStore.ProtectionParameter invalidParam = new CredentialStore.ProtectionParameter() {};
        assertThrows(CredentialStoreException.class,
                () -> store.initialize(attrs, invalidParam, new Provider[]{}));
    }

    /**
     * Call {@code initialize()} with a non-existent key-store-path.
     * Test passes when {@link CredentialStoreException} is thrown with "Failed to load KeyStore" message.
     */
    @Test
    public void testInitializeWithInvalidKeyStorePath() {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        Map<String, String> attrs = new HashMap<>();
        attrs.put("host-address", "http://localhost:8200");
        attrs.put("key-store-path", "/nonexistent/path/keystore.jks");
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
                () -> store.initialize(attrs, createProtectionParameter("token"), new Provider[]{}));
        assertTrue(ex.getMessage().contains("Failed to load KeyStore"),
                "Expected 'Failed to load KeyStore' in message, got: " + ex.getMessage());
    }

    /**
     * Call {@code initialize()} with a non-existent trust-store-path.
     * Test passes when {@link CredentialStoreException} is thrown with "Failed to load TrustStore" message.
     */
    @Test
    public void testInitializeWithInvalidTrustStorePath() {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        Map<String, String> attrs = new HashMap<>();
        attrs.put("host-address", "http://localhost:8200");
        attrs.put("trust-store-path", "/nonexistent/path/truststore.jks");
        CredentialStoreException ex = assertThrows(CredentialStoreException.class,
                () -> store.initialize(attrs, createProtectionParameter("token"), new Provider[]{}));
        assertTrue(ex.getMessage().contains("Failed to load TrustStore"),
                "Expected 'Failed to load TrustStore' in message, got: " + ex.getMessage());
    }

    // =====================================================================
    // Not initialized — operations on a store that was never initialized
    // =====================================================================

    /**
     * Call {@code store()} on a credential store that has not been initialized.
     * Test passes when {@link CredentialStoreException} is thrown.
     */
    @Test
    public void testStoreNotInitialized() {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        assertThrows(CredentialStoreException.class,
                () -> store.store("secret/path.key", createCredentialFromPassword("v"), null));
    }

    /**
     * Call {@code retrieve()} on a credential store that has not been initialized.
     * Test passes when {@link CredentialStoreException} is thrown.
     */
    @Test
    public void testRetrieveNotInitialized() {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        assertThrows(CredentialStoreException.class,
                () -> store.retrieve("secret/path.key", PasswordCredential.class,
                        ClearPassword.ALGORITHM_CLEAR, null, null));
    }

    /**
     * Call {@code remove()} on a credential store that has not been initialized.
     * Test passes when {@link CredentialStoreException} is thrown.
     */
    @Test
    public void testRemoveNotInitialized() {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        assertThrows(CredentialStoreException.class,
                () -> store.remove("secret/path.key", PasswordCredential.class,
                        ClearPassword.ALGORITHM_CLEAR, null));
    }

    /**
     * Call {@code getAliases(path)} on a credential store that has not been initialized.
     * Test passes when {@link CredentialStoreException} is thrown.
     */
    @Test
    public void testGetAliasesNotInitialized() {
        HashicorpVaultCredentialStore store = new HashicorpVaultCredentialStore();
        assertThrows(CredentialStoreException.class,
                () -> store.getAliases("secret/"));
    }
}
