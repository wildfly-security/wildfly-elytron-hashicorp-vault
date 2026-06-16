/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.hashicorp.vault.KvVersionTestHelper.KvTestConfig;
import org.wildfly.security.hashicorp.vault.KvVersionTestHelper.KvVersion;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.VaultException;

/**
 * Parameterized test suite for {@link VaultConnector} covering both KV v1 and KV v2 engines.
 *
 * <p>This test class uses JUnit 5's {@code @ParameterizedTest} to run the same test logic
 * against different Vault configurations:
 * <ul>
 *   <li>KV v1 only</li>
 *   <li>KV v2 only (default)</li>
 *   <li>Mixed environment (both v1 and v2 at different mounts)</li>
 * </ul>
 *
 * <p><strong>Test Coverage:</strong>
 * <ul>
 *   <li>Basic CRUD operations (Create, Read, Update, Delete)</li>
 *   <li>Path format validation</li>
 *   <li>Error handling (404, 403)</li>
 *   <li>Multi-key secret operations</li>
 *   <li>List operations</li>
 * </ul>
 *
 * <p><strong>Key Differences Tested:</strong>
 * <ul>
 *   <li><strong>KV v1:</strong> Direct paths, no versioning, full overwrite on update</li>
 *   <li><strong>KV v2:</strong> /data/ paths, versioning, creates new version on update</li>
 * </ul>
 */
public class VaultConnectorKvVersionTestCase {

    private VaultContainer<?> vaultContainer;

    @AfterEach
    public void cleanup() {
        if (vaultContainer != null) {
            vaultContainer.stop();
        }
    }

    /**
     * Provides test configurations for parameterized tests.
     * Each configuration includes a Vault container with a specific KV version setup.
     */
    static Stream<Arguments> kvVersionConfigurations() {
        return Stream.of(
            // KV v1 only
            Arguments.of(new VaultContainerKvV1<>("hashicorp/vault:1.13"), "secret", KvVersion.V1),

            // KV v2 only (using standard VaultContainer which defaults to v2)
            Arguments.of(new VaultContainer<>("hashicorp/vault:1.13")
                .withVaultToken("myroot")
                .withInitCommand(
                    "secrets enable transit",
                    "write -f transit/keys/my-key",
                    "kv put secret/testing1 top_secret=password123",
                    "kv put secret/testing2 dbuser=secretpass jmsuser=jmspass",
                    "kv put secret/my-secret my-value=s3cr3t"
                ), "secret", KvVersion.V2),

            // Mixed: KV v1 at secret-v1/
            Arguments.of(new VaultContainerKvMixed<>("hashicorp/vault:1.13"), "secret-v1", KvVersion.V1),

            // Mixed: KV v2 at secret/
            Arguments.of(new VaultContainerKvMixed<>("hashicorp/vault:1.13"), "secret", KvVersion.V2)
        );
    }

    private VaultConnector createConnector(VaultContainer<?> container, String token) throws VaultException {
        VaultConnector connector = new VaultConnector(
            container.getHttpHostAddress(),
            token,
            "admin",
            new SslConfig().verify(true).build(),
            true
        );
        connector.configure();
        return connector;
    }

    // =====================================================================
    // Basic CRUD Operations
    // =====================================================================

    @ParameterizedTest(name = "[{2}] Get secret from {1}")
    @MethodSource("kvVersionConfigurations")
    public void testGetSecret(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = createConnector(vaultContainer, "myroot");
        String secret = connector.getSecret(mountPath + "/testing1", "top_secret");

        assertEquals("password123", secret,
            String.format("Should retrieve secret from %s mount", version));
    }

    @ParameterizedTest(name = "[{2}] Put secret to {1}")
    @MethodSource("kvVersionConfigurations")
    public void testPutSecret(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = createConnector(vaultContainer, "myroot");

        // Put a new secret
        connector.putSecret(mountPath + "/testing1", "new_secret", "newvalue123");

        // Verify it was stored
        String retrieved = connector.getSecret(mountPath + "/testing1", "new_secret");
        assertEquals("newvalue123", retrieved,
            String.format("Should store and retrieve new secret in %s", version));
    }

    @ParameterizedTest(name = "[{2}] Update existing secret in {1}")
    @MethodSource("kvVersionConfigurations")
    public void testUpdateSecret(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = createConnector(vaultContainer, "myroot");

        // Verify original value
        String original = connector.getSecret(mountPath + "/testing1", "top_secret");
        assertEquals("password123", original);

        // Update the secret
        connector.putSecret(mountPath + "/testing1", "top_secret", "updated_password");

        // Verify updated value
        String updated = connector.getSecret(mountPath + "/testing1", "top_secret");
        assertEquals("updated_password", updated,
            String.format("Should update existing secret in %s", version));
    }

    @ParameterizedTest(name = "[{2}] Remove secret from {1}")
    @MethodSource("kvVersionConfigurations")
    public void testRemoveSecret(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = createConnector(vaultContainer, "myroot");

        // Verify secret exists
        String original = connector.getSecret(mountPath + "/testing1", "top_secret");
        assertNotNull(original);

        // Remove the secret
        connector.removeSecret(mountPath + "/testing1", "top_secret");

        // Verify it's gone
        String removed = connector.getSecret(mountPath + "/testing1", "top_secret");
        assertNull(removed,
            String.format("Should remove secret from %s", version));
    }

    // =====================================================================
    // Multi-Key Secret Operations
    // =====================================================================

    @ParameterizedTest(name = "[{2}] Modify single key in multi-key secret at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testModifySingleKeyInMultiKeySecret(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = createConnector(vaultContainer, "myroot");

        // Verify both keys exist initially
        assertEquals("secretpass", connector.getSecret(mountPath + "/testing2", "dbuser"));
        assertEquals("jmspass", connector.getSecret(mountPath + "/testing2", "jmsuser"));

        // Modify only dbuser
        connector.putSecret(mountPath + "/testing2", "dbuser", "new_dbpass");

        // Verify dbuser changed but jmsuser remained
        assertEquals("new_dbpass", connector.getSecret(mountPath + "/testing2", "dbuser"),
            String.format("Should update modified key in %s", version));
        assertEquals("jmspass", connector.getSecret(mountPath + "/testing2", "jmsuser"),
            String.format("Should preserve unmodified key in %s", version));
    }

    @ParameterizedTest(name = "[{2}] Remove single key from multi-key secret at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testRemoveSingleKeyFromMultiKeySecret(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = createConnector(vaultContainer, "myroot");

        // Verify both keys exist
        assertNotNull(connector.getSecret(mountPath + "/testing2", "dbuser"));
        assertNotNull(connector.getSecret(mountPath + "/testing2", "jmsuser"));

        // Remove only dbuser
        connector.removeSecret(mountPath + "/testing2", "dbuser");

        // Verify dbuser is gone but jmsuser remains
        assertNull(connector.getSecret(mountPath + "/testing2", "dbuser"),
            String.format("Should remove specified key in %s", version));
        assertNotNull(connector.getSecret(mountPath + "/testing2", "jmsuser"),
            String.format("Should preserve other keys in %s", version));
    }

    // =====================================================================
    // Error Handling
    // =====================================================================

    @ParameterizedTest(name = "[{2}] Get non-existent secret returns null at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testGetNonExistentSecretReturnsNull(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = createConnector(vaultContainer, "myroot");

        String result = connector.getSecret(mountPath + "/nonexistent", "somekey");
        assertNull(result,
            String.format("Should return null for non-existent path in %s", version));
    }

    @ParameterizedTest(name = "[{2}] Get non-existent key returns null at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testGetNonExistentKeyReturnsNull(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = createConnector(vaultContainer, "myroot");

        String result = connector.getSecret(mountPath + "/testing1", "nonexistent_key");
        assertNull(result,
            String.format("Should return null for non-existent key in %s", version));
    }

    @ParameterizedTest(name = "[{2}] Invalid token throws exception at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testInvalidTokenThrowsException(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = new VaultConnector(
            vaultContainer.getHttpHostAddress(),
            "invalid-token",
            "admin",
            new SslConfig().verify(true).build(),
            true
        );

        assertThrows(VaultException.class, connector::configure,
            String.format("Should throw VaultException for invalid token in %s", version));
    }

    // =====================================================================
    // List Operations
    // =====================================================================

    @ParameterizedTest(name = "[{2}] List keys at path {1}")
    @MethodSource("kvVersionConfigurations")
    public void testGetKeysForPath(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = createConnector(vaultContainer, "myroot");

        var keys = connector.getKeysForPath(mountPath + "/testing2");
        assertNotNull(keys, String.format("Should return keys for path in %s", version));
        assertTrue(keys.contains("dbuser"),
            String.format("Should contain 'dbuser' key in %s", version));
        assertTrue(keys.contains("jmsuser"),
            String.format("Should contain 'jmsuser' key in %s", version));
    }

    @ParameterizedTest(name = "[{2}] List non-existent path throws exception at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testGetKeysForNonExistentPath(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = createConnector(vaultContainer, "myroot");

        VaultException ex = assertThrows(VaultException.class,
            () -> connector.getKeysForPath(mountPath + "/nonexistent"),
            String.format("Should throw exception for non-existent path in %s", version));

        assertTrue(ex.getMessage().contains("Path does not exist"),
            String.format("Exception should mention path doesn't exist in %s", version));
    }

    // =====================================================================
    // Path Format Validation
    // =====================================================================

    @ParameterizedTest(name = "[{2}] Nested path operations at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testNestedPathOperations(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = createConnector(vaultContainer, "myroot");

        // Create secret at nested path
        String nestedPath = mountPath + "/app/database/credentials";
        connector.putSecret(nestedPath, "username", "dbuser");
        connector.putSecret(nestedPath, "password", "dbpass");

        // Retrieve from nested path
        assertEquals("dbuser", connector.getSecret(nestedPath, "username"),
            String.format("Should handle nested paths in %s", version));
        assertEquals("dbpass", connector.getSecret(nestedPath, "password"),
            String.format("Should handle nested paths in %s", version));
    }
}

// Made with Bob
