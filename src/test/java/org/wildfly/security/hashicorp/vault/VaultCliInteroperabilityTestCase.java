/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.wildfly.security.hashicorp.vault.KvVersionTestHelper.cliGetSecret;
import static org.wildfly.security.hashicorp.vault.KvVersionTestHelper.cliPutSecret;

import java.util.stream.Stream;

import io.restassured.path.json.JsonPath;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.containers.Container;
import org.testcontainers.vault.VaultContainer;
import org.wildfly.security.hashicorp.vault.KvVersionTestHelper.KvVersion;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.VaultException;

/**
 * Interoperability test suite validating that the Java API and Vault CLI can work together.
 *
 * <p>This test class verifies that:
 * <ul>
 *   <li>Secrets written by the Vault CLI can be read by the Java API</li>
 *   <li>Secrets written by the Java API can be read by the Vault CLI</li>
 *   <li>Modifications made via CLI are visible to the Java API</li>
 *   <li>Modifications made via Java API are visible to the CLI</li>
 *   <li>Credential format and encoding are compatible between CLI and API</li>
 * </ul>
 *
 * <p><strong>Why This Matters:</strong>
 * In real-world scenarios, users often mix CLI and API usage. For example:
 * <ul>
 *   <li>DevOps teams use CLI for initial setup and manual operations</li>
 *   <li>Applications use the Java API for runtime secret access</li>
 *   <li>CI/CD pipelines may use CLI while apps use API</li>
 * </ul>
 *
 * <p>These tests ensure seamless interoperability across both KV v1 and v2.
 */
public class VaultCliInteroperabilityTestCase {

    private VaultContainer<?> vaultContainer;

    @AfterEach
    public void cleanup() {
        if (vaultContainer != null) {
            vaultContainer.stop();
        }
    }

    /**
     * Provides test configurations for parameterized tests.
     */
    static Stream<Arguments> kvVersionConfigurations() {
        return Stream.of(
            // KV v1 only
            Arguments.of(new VaultContainerKvV1<>("hashicorp/vault:1.13"), "secret", KvVersion.V1),

            // KV v2 only
            Arguments.of(new VaultContainer<>("hashicorp/vault:1.13")
                .withVaultToken("myroot")
                .withInitCommand(
                    "secrets enable transit",
                    "write -f transit/keys/my-key"
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
    // CLI Write → Java API Read
    // =====================================================================

    @ParameterizedTest(name = "[{2}] Read CLI-written secret via Java API at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testReadCliWrittenSecret(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        // Write secret using Vault CLI
        Container.ExecResult cliResult = cliPutSecret(
            vaultContainer,
            mountPath + "/cli-test",
            "username=admin",
            "password=secret123"
        );
        assertEquals(0, cliResult.getExitCode(),
            String.format("CLI write should succeed in %s: %s", version, cliResult.getStderr()));

        // Read using Java API
        VaultConnector connector = createConnector(vaultContainer, "myroot");
        String username = connector.getSecret(mountPath + "/cli-test", "username");
        String password = connector.getSecret(mountPath + "/cli-test", "password");

        assertEquals("admin", username,
            String.format("Should read CLI-written username in %s", version));
        assertEquals("secret123", password,
            String.format("Should read CLI-written password in %s", version));
    }

    @ParameterizedTest(name = "[{2}] Read CLI-written multi-key secret via Java API at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testReadCliWrittenMultiKeySecret(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        // Write multi-key secret using CLI
        Container.ExecResult cliResult = cliPutSecret(
            vaultContainer,
            mountPath + "/app-config",
            "db_host=localhost",
            "db_port=5432",
            "db_name=myapp",
            "db_user=appuser",
            "db_pass=apppass"
        );
        assertEquals(0, cliResult.getExitCode(),
            String.format("CLI write should succeed in %s", version));

        // Read all keys using Java API
        VaultConnector connector = createConnector(vaultContainer, "myroot");
        assertEquals("localhost", connector.getSecret(mountPath + "/app-config", "db_host"));
        assertEquals("5432", connector.getSecret(mountPath + "/app-config", "db_port"));
        assertEquals("myapp", connector.getSecret(mountPath + "/app-config", "db_name"));
        assertEquals("appuser", connector.getSecret(mountPath + "/app-config", "db_user"));
        assertEquals("apppass", connector.getSecret(mountPath + "/app-config", "db_pass"));
    }

    // =====================================================================
    // Java API Write → CLI Read
    // =====================================================================

    @ParameterizedTest(name = "[{2}] Read Java-written secret via CLI at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testReadJavaWrittenSecretViaCli(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        // Write secret using Java API
        VaultConnector connector = createConnector(vaultContainer, "myroot");
        connector.putSecret(mountPath + "/java-test", "api_key", "key123");
        connector.putSecret(mountPath + "/java-test", "api_secret", "secret456");

        // Read using Vault CLI
        Container.ExecResult cliResult = cliGetSecret(vaultContainer, mountPath + "/java-test");
        assertEquals(0, cliResult.getExitCode(),
            String.format("CLI read should succeed in %s: %s", version, cliResult.getStderr()));

        // Parse JSON output using RestAssured JsonPath
        String output = cliResult.getStdout();
        JsonPath json = JsonPath.from(output);

        String apiKey, apiSecret;
        if (version == KvVersion.V2) {
            // KV v2 has nested structure: data.data.key
            apiKey = json.getString("data.data.api_key");
            apiSecret = json.getString("data.data.api_secret");
        } else {
            // KV v1 has flat structure: data.key
            apiKey = json.getString("data.api_key");
            apiSecret = json.getString("data.api_secret");
        }

        assertEquals("key123", apiKey,
            String.format("CLI should read Java-written api_key in %s", version));
        assertEquals("secret456", apiSecret,
            String.format("CLI should read Java-written api_secret in %s", version));
    }

    @ParameterizedTest(name = "[{2}] Read Java-written multi-key secret via CLI at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testReadJavaWrittenMultiKeySecretViaCli(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        // Write multi-key secret using Java API
        VaultConnector connector = createConnector(vaultContainer, "myroot");
        connector.putSecret(mountPath + "/service-config", "host", "api.example.com");
        connector.putSecret(mountPath + "/service-config", "port", "443");
        connector.putSecret(mountPath + "/service-config", "protocol", "https");

        // Read using CLI
        Container.ExecResult cliResult = cliGetSecret(vaultContainer, mountPath + "/service-config");
        assertEquals(0, cliResult.getExitCode(),
            String.format("CLI read should succeed in %s", version));

        // Parse and verify using RestAssured JsonPath
        JsonPath json = JsonPath.from(cliResult.getStdout());

        String host, port, protocol;
        if (version == KvVersion.V2) {
            host = json.getString("data.data.host");
            port = json.getString("data.data.port");
            protocol = json.getString("data.data.protocol");
        } else {
            host = json.getString("data.host");
            port = json.getString("data.port");
            protocol = json.getString("data.protocol");
        }

        assertEquals("api.example.com", host);
        assertEquals("443", port);
        assertEquals("https", protocol);
    }

    // =====================================================================
    // Modification Interoperability
    // =====================================================================

    @ParameterizedTest(name = "[{2}] Modify CLI-written secret via Java API at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testModifyCliWrittenSecretViaJavaApi(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        // Write initial secret using CLI
        cliPutSecret(vaultContainer, mountPath + "/modify-test", "value=original");

        // Modify using Java API
        VaultConnector connector = createConnector(vaultContainer, "myroot");
        connector.putSecret(mountPath + "/modify-test", "value", "modified");

        // Verify modification via CLI
        Container.ExecResult cliResult = cliGetSecret(vaultContainer, mountPath + "/modify-test");
        assertEquals(0, cliResult.getExitCode());

        JsonPath json = JsonPath.from(cliResult.getStdout());

        String value;
        if (version == KvVersion.V2) {
            value = json.getString("data.data.value");
        } else {
            value = json.getString("data.value");
        }

        assertEquals("modified", value,
            String.format("CLI should see Java API modification in %s", version));
    }

    @ParameterizedTest(name = "[{2}] Modify Java-written secret via CLI at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testModifyJavaWrittenSecretViaCli(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        // Write initial secret using Java API
        VaultConnector connector = createConnector(vaultContainer, "myroot");
        connector.putSecret(mountPath + "/modify-test2", "status", "initial");

        // Modify using CLI
        Container.ExecResult cliResult = cliPutSecret(
            vaultContainer,
            mountPath + "/modify-test2",
            "status=updated"
        );
        assertEquals(0, cliResult.getExitCode());

        // Verify modification via Java API
        String status = connector.getSecret(mountPath + "/modify-test2", "status");
        assertEquals("updated", status,
            String.format("Java API should see CLI modification in %s", version));
    }

    @ParameterizedTest(name = "[{2}] Modify single key preserves other keys (CLI→Java→CLI) at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testModifySingleKeyPreservesOthersCliJavaCli(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        // Write multi-key secret using CLI
        cliPutSecret(vaultContainer, mountPath + "/multi-key", "key1=value1", "key2=value2", "key3=value3");

        // Modify one key using Java API
        VaultConnector connector = createConnector(vaultContainer, "myroot");
        connector.putSecret(mountPath + "/multi-key", "key2", "modified");

        // Verify all keys via CLI
        Container.ExecResult cliResult = cliGetSecret(vaultContainer, mountPath + "/multi-key");
        assertEquals(0, cliResult.getExitCode());

        JsonPath json = JsonPath.from(cliResult.getStdout());

        String key1, key2, key3;
        if (version == KvVersion.V2) {
            key1 = json.getString("data.data.key1");
            key2 = json.getString("data.data.key2");
            key3 = json.getString("data.data.key3");
        } else {
            key1 = json.getString("data.key1");
            key2 = json.getString("data.key2");
            key3 = json.getString("data.key3");
        }

        assertEquals("value1", key1,
            String.format("Unmodified key1 should be preserved in %s", version));
        assertEquals("modified", key2,
            String.format("Modified key2 should be updated in %s", version));
        assertEquals("value3", key3,
            String.format("Unmodified key3 should be preserved in %s", version));
    }

    // =====================================================================
    // Special Characters and Encoding
    // =====================================================================

    @ParameterizedTest(name = "[{2}] Handle special characters in values at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testSpecialCharactersInValues(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = createConnector(vaultContainer, "myroot");

        // Test various special characters
        String specialValue = "p@ssw0rd!#$%^&*(){}[]|\\:;\"'<>,.?/~`";

        // Write using Java API
        connector.putSecret(mountPath + "/special-chars", "password", specialValue);

        // Read using CLI
        Container.ExecResult cliResult = cliGetSecret(vaultContainer, mountPath + "/special-chars");
        assertEquals(0, cliResult.getExitCode());

        JsonPath json = JsonPath.from(cliResult.getStdout());

        String password;
        if (version == KvVersion.V2) {
            password = json.getString("data.data.password");
        } else {
            password = json.getString("data.password");
        }

        assertEquals(specialValue, password,
            String.format("Special characters should be preserved in %s", version));

        // Verify round-trip via Java API
        String retrieved = connector.getSecret(mountPath + "/special-chars", "password");
        assertEquals(specialValue, retrieved,
            String.format("Special characters should round-trip correctly in %s", version));
    }

    @ParameterizedTest(name = "[{2}] Handle empty values at {1}")
    @MethodSource("kvVersionConfigurations")
    public void testEmptyValues(VaultContainer<?> container, String mountPath, KvVersion version) throws Exception {
        vaultContainer = container;
        vaultContainer.start();

        VaultConnector connector = createConnector(vaultContainer, "myroot");

        // Write empty value using Java API
        connector.putSecret(mountPath + "/empty-test", "empty_key", "");

        // Read using CLI
        Container.ExecResult cliResult = cliGetSecret(vaultContainer, mountPath + "/empty-test");
        assertEquals(0, cliResult.getExitCode());

        JsonPath json = JsonPath.from(cliResult.getStdout());

        String emptyKey;
        if (version == KvVersion.V2) {
            emptyKey = json.getString("data.data.empty_key");
        } else {
            emptyKey = json.getString("data.empty_key");
        }

        assertNotNull(emptyKey,
            String.format("Empty key should exist in %s", version));
        assertEquals("", emptyKey,
            String.format("Empty value should be preserved in %s", version));
    }
}

// Made with Bob
