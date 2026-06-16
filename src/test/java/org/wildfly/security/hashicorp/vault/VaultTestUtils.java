/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

import org.testcontainers.vault.VaultContainer;

public class VaultTestUtils {

    /**
     * Starts a Vault test container with predefined secrets.
     */
    public static VaultContainer<?> startVaultTestContainer() {
        VaultContainer<?> vaultTestContainer = new VaultContainer<>("hashicorp/vault:1.13")
                .withVaultToken("myroot")
                .withInitCommand(
                        "secrets enable transit",
                        "write -f transit/keys/my-key",
                        "kv put secret/testing1 top_secret=password123",
                        "kv put secret/testing2 dbuser=secretpass jmsuser=jmspass"
                );
        vaultTestContainer.start();
        return vaultTestContainer;
    }

    /**
     * Remove directory and its content
     * @param dir directory to cleanup
     */
    public static void cleanupDir(final Path dir) {
        if (!Files.exists(dir)) return;

        try (Stream<Path> paths = Files.walk(dir)) {
            // Delete in reverse order (children first, then parent)
            paths.sorted(Comparator.reverseOrder())
                    .forEach(path -> {
                        try {
                            Files.delete(path);
                        } catch (IOException e) {
                            throw new RuntimeException("Failed to delete " + path, e);
                        }
                    });
        } catch (IOException e) {
            throw new RuntimeException("Failed to walk directory " + dir, e);
        }
    }
}
