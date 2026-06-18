/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import org.testcontainers.containers.Container;
import org.testcontainers.vault.VaultContainer;

import java.io.IOException;

/**
 * Helper utilities for KV version testing.
 *
 * <p>This class provides common functionality for testing HashiCorp Vault KV Secrets Engine
 * versions (v1 and v2), including CLI command execution, path validation, and test data setup.
 */
public class KvVersionTestHelper {

    /**
     * Represents the KV engine version.
     */
    public enum KvVersion {
        V1(1, "KV v1"),
        V2(2, "KV v2");

        private final int version;
        private final String displayName;

        KvVersion(int version, String displayName) {
            this.version = version;
            this.displayName = displayName;
        }

        public int getVersion() {
            return version;
        }

        public String getDisplayName() {
            return displayName;
        }

        @Override
        public String toString() {
            return displayName;
        }
    }

    /**
     * Configuration for a KV version test scenario.
     */
    public static class KvTestConfig {
        private final VaultContainer<?> container;
        private final String mountPath;
        private final KvVersion version;
        private final String token;

        public KvTestConfig(VaultContainer<?> container, String mountPath, KvVersion version, String token) {
            this.container = container;
            this.mountPath = mountPath;
            this.version = version;
            this.token = token;
        }

        public VaultContainer<?> getContainer() {
            return container;
        }

        public String getMountPath() {
            return mountPath;
        }

        public KvVersion getVersion() {
            return version;
        }

        public String getToken() {
            return token;
        }

        public String getHostAddress() {
            return container.getHttpHostAddress();
        }

        @Override
        public String toString() {
            return String.format("%s (mount: %s)", version.getDisplayName(), mountPath);
        }
    }

    /**
     * Executes a Vault CLI command in the container.
     *
     * @param container the Vault container
     * @param command the CLI command arguments (e.g., "kv", "get", "secret/path")
     * @return the command execution result
     * @throws IOException if command execution fails
     * @throws InterruptedException if command execution is interrupted
     */
    public static Container.ExecResult execVaultCommand(VaultContainer<?> container, String... command)
            throws IOException, InterruptedException {
        String[] fullCommand = new String[command.length + 1];
        fullCommand[0] = "vault";
        System.arraycopy(command, 0, fullCommand, 1, command.length);
        return container.execInContainer(fullCommand);
    }

    /**
     * Writes a secret using the Vault CLI.
     *
     * @param container the Vault container
     * @param path the secret path (e.g., "secret/myapp")
     * @param keyValuePairs key-value pairs in the format "key=value"
     * @return the command execution result
     * @throws IOException if command execution fails
     * @throws InterruptedException if command execution is interrupted
     */
    public static Container.ExecResult cliPutSecret(VaultContainer<?> container, String path, String... keyValuePairs)
            throws IOException, InterruptedException {
        String[] command = new String[keyValuePairs.length + 3];
        command[0] = "kv";
        command[1] = "put";
        command[2] = path;
        System.arraycopy(keyValuePairs, 0, command, 3, keyValuePairs.length);
        return execVaultCommand(container, command);
    }

    /**
     * Reads a secret using the Vault CLI.
     *
     * @param container the Vault container
     * @param path the secret path (e.g., "secret/myapp")
     * @return the command execution result
     * @throws IOException if command execution fails
     * @throws InterruptedException if command execution is interrupted
     */
    public static Container.ExecResult cliGetSecret(VaultContainer<?> container, String path)
            throws IOException, InterruptedException {
        return execVaultCommand(container, "kv", "get", "-format=json", path);
    }

    /**
     * Deletes a secret using the Vault CLI.
     *
     * @param container the Vault container
     * @param path the secret path (e.g., "secret/myapp")
     * @return the command execution result
     * @throws IOException if command execution fails
     * @throws InterruptedException if command execution is interrupted
     */
    public static Container.ExecResult cliDeleteSecret(VaultContainer<?> container, String path)
            throws IOException, InterruptedException {
        return execVaultCommand(container, "kv", "delete", path);
    }

    /**
     * Lists secrets at a path using the Vault CLI.
     *
     * @param container the Vault container
     * @param path the secret path (e.g., "secret/")
     * @return the command execution result
     * @throws IOException if command execution fails
     * @throws InterruptedException if command execution is interrupted
     */
    public static Container.ExecResult cliListSecrets(VaultContainer<?> container, String path)
            throws IOException, InterruptedException {
        return execVaultCommand(container, "kv", "list", "-format=json", path);
    }

    /**
     * Constructs the API path for a secret based on KV version.
     *
     * <p>KV v1 uses direct paths: {@code /v1/secret/path/to/secret}
     * <p>KV v2 uses data paths: {@code /v1/secret/data/path/to/secret}
     *
     * @param mountPath the mount path (e.g., "secret")
     * @param secretPath the secret path relative to mount (e.g., "myapp/db")
     * @param version the KV version
     * @return the full API path
     */
    public static String constructApiPath(String mountPath, String secretPath, KvVersion version) {
        if (version == KvVersion.V1) {
            return mountPath + "/" + secretPath;
        } else {
            return mountPath + "/data/" + secretPath;
        }
    }

    /**
     * Constructs the metadata API path for a secret (KV v2 only).
     *
     * @param mountPath the mount path (e.g., "secret")
     * @param secretPath the secret path relative to mount (e.g., "myapp/db")
     * @return the metadata API path
     * @throws IllegalArgumentException if called for KV v1
     */
    public static String constructMetadataPath(String mountPath, String secretPath) {
        return mountPath + "/metadata/" + secretPath;
    }

    /**
     * Validates that a secret path is correctly formatted for the given KV version.
     *
     * @param path the full secret path
     * @param version the expected KV version
     * @return true if the path format matches the version
     */
    public static boolean isValidPathForVersion(String path, KvVersion version) {
        if (path == null || path.isEmpty()) {
            return false;
        }

        if (version == KvVersion.V1) {
            // KV v1 paths should NOT contain /data/ or /metadata/
            return !path.contains("/data/") && !path.contains("/metadata/");
        } else {
            // KV v2 paths for data operations should contain /data/
            // (metadata paths are handled separately)
            return path.contains("/data/");
        }
    }

    /**
     * Extracts the secret name from a full path.
     *
     * @param path the full secret path (e.g., "secret/data/myapp" or "secret/myapp")
     * @return the secret name (e.g., "myapp")
     */
    public static String extractSecretName(String path) {
        if (path == null || path.isEmpty()) {
            return "";
        }

        // Remove /data/ or /metadata/ if present
        String normalized = path.replace("/data/", "/").replace("/metadata/", "/");

        // Get the last segment
        int lastSlash = normalized.lastIndexOf('/');
        return lastSlash >= 0 ? normalized.substring(lastSlash + 1) : normalized;
    }

    /**
     * Creates a display name for parameterized tests.
     *
     * @param config the test configuration
     * @return a descriptive display name
     */
    public static String createDisplayName(KvTestConfig config) {
        return String.format("[%s] mount=%s", config.getVersion().getDisplayName(), config.getMountPath());
    }

    /**
     * Waits for the Vault container to be fully ready.
     *
     * @param container the Vault container
     * @param maxWaitSeconds maximum time to wait in seconds
     * @throws InterruptedException if waiting is interrupted
     */
    public static void waitForVaultReady(VaultContainer<?> container, int maxWaitSeconds)
            throws InterruptedException {
        int waited = 0;
        while (waited < maxWaitSeconds) {
            try {
                Container.ExecResult result = execVaultCommand(container, "status");
                if (result.getExitCode() == 0 || result.getExitCode() == 2) {
                    // Exit code 0 = unsealed, 2 = sealed (both mean Vault is running)
                    return;
                }
            } catch (IOException e) {
                // Container not ready yet
            }
            Thread.sleep(1000);
            waited++;
        }
        throw new IllegalStateException("Vault container did not become ready within " + maxWaitSeconds + " seconds");
    }
}
