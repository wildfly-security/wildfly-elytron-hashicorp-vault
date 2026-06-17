/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.wildfly.security.hashicorp.vault._private.HashiCorpVaultLogger.ROOT_LOGGER;

import java.util.Map;

/**
 * Resolves key paths within Vault secret data.
 *
 * <p>Supports two modes of key path resolution:
 * <ul>
 *   <li><b>Simple key lookup:</b> When the key path contains no {@code /} separator,
 *       performs a direct lookup in the data map. This supports keys with dots in their names.</li>
 *   <li><b>Nested JSON traversal:</b> When the key path contains {@code /} separators,
 *       traverses nested maps using each segment as a key. Dots within segments are preserved
 *       as part of the key name.</li>
 * </ul>
 *
 * <p>Examples:
 * <pre>
 * Map<String, Object> data = Map.of(
 *     "password", "secret123",
 *     "db.host", "localhost",
 *     "database", Map.of(
 *         "host", "prod.db.com",
 *         "credentials", Map.of(
 *             "user", "admin",
 *             "pass", "secret"
 *         )
 *     ),
 *     "my.app", Map.of(
 *         "config.key", "value123"
 *     )
 * );
 *
 * // Simple key lookups (no / in key path)
 * resolveKeyPath(data, "password")           → "secret123"
 * resolveKeyPath(data, "db.host")            → "localhost"  (dots in key name)
 *
 * // Nested JSON traversal (with / in key path)
 * resolveKeyPath(data, "database/host")                    → "prod.db.com"
 * resolveKeyPath(data, "database/credentials/pass")        → "secret"
 * resolveKeyPath(data, "my.app/config.key")                → "value123"  (dots in segment)
 * </pre>
 */
class KeyPathResolver {

    /**
     * Extract value from Vault secret data using key path.
     *
     * <p>If the key path contains no {@code /} separator, performs a simple lookup
     * in the data map (supporting dots in key names). If the key path contains
     * {@code /} separators, traverses nested maps using each segment as a key.
     *
     * @param data the secret data map from Vault
     * @param keyPath the key path from alias (after ? delimiter, already URL-decoded)
     * @return the extracted value as a string, or {@code null} if not found
     * @throws IllegalArgumentException if keyPath is null or empty
     */
    public static String resolveKeyPath(Map<String, Object> data, String keyPath) {
        if (keyPath == null || keyPath.isEmpty()) {
            throw ROOT_LOGGER.keyPathCannotBeNullOrEmpty();
        }

        if (data == null) {
            return null;
        }

        // Check if key path contains / (nested path)
        if (!keyPath.contains("/")) {
            // Simple key - direct lookup (supports dots in key name)
            Object value = data.get(keyPath);
            return value != null ? value.toString() : null;
        }

        // Nested path - traverse using /
        String[] segments = keyPath.split("/");
        Object current = data;

        for (int i = 0; i < segments.length; i++) {
            String segment = segments[i];

            // Validate segment is not empty
            if (segment.isEmpty()) {
                throw ROOT_LOGGER.keyPathContainsEmptySegment(keyPath);
            }

            if (!(current instanceof Map)) {
                // Can't traverse further - not a map
                return null;
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> currentMap = (Map<String, Object>) current;

            // Look up this segment (segment can contain dots)
            current = currentMap.get(segment);

            if (current == null) {
                return null;
            }

            // If this is the last segment, return the value
            if (i == segments.length - 1) {
                return current.toString();
            }
        }

        return null;
    }
}
