/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.wildfly.security.hashicorp.vault._private.HashiCorpVaultLogger.ROOT_LOGGER;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

/**
 * Represents a parsed Vault alias in the new format.
 *
 * <p>Format: {@code [engine=TYPE][@mount-path]#secret-path?key-path}
 *
 * <p>Components:
 * <ul>
 *   <li>{@code engine=TYPE} - Optional engine type specification (e.g., {@code engine=KVv1}, {@code engine=KVv2})</li>
 *   <li>{@code @mount-path} - Optional mount path (e.g., {@code @secret}, {@code @team/backend})</li>
 *   <li>{@code #secret-path} - Required secret path (e.g., {@code #myapp/database})</li>
 *   <li>{@code ?key-path} - Required key path (e.g., {@code ?password}, {@code ?database/credentials/password})</li>
 * </ul>
 *
 * <p>Examples:
 * <ul>
 *   <li>{@code #myapp/database?password} - Simple key with defaults</li>
 *   <li>{@code engine=KVv1@secret-v1#myapp?password} - Explicit engine and mount</li>
 *   <li>{@code #my.app.config?db.host} - Dots in secret path and key name</li>
 *   <li>{@code #myapp/database?database/credentials/password} - Nested JSON path</li>
 * </ul>
 */
class VaultAlias {

    private String engineType;
    private String mountPath;
    private String secretPath;
    private String keyPath;

    /**
     * Private constructor - use {@link #parse(String)} or {@link #parse(String, String, String)} to create instances.
     */
    private VaultAlias() {
    }

    /**
     * Parse a vault alias string using default engine type and mount path.
     *
     * @param alias the alias string to parse
     * @return the parsed VaultAlias
     * @throws IllegalArgumentException if the alias format is invalid
     */
    public static VaultAlias parse(String alias) {
        return parse(alias, "KVv2", "secret");
    }

    /**
     * Parse a vault alias string with specified defaults for engine type and mount path.
     *
     * @param alias the alias string to parse
     * @param defaultEngineType the default engine type to use if not specified in alias
     * @param defaultMountPath the default mount path to use if not specified in alias
     * @return the parsed VaultAlias
     * @throws IllegalArgumentException if the alias format is invalid
     */
    public static VaultAlias parse(String alias, String defaultEngineType, String defaultMountPath) {
        if (alias == null || alias.isEmpty()) {
            throw ROOT_LOGGER.aliasCannotBeNullOrEmpty();
        }

        VaultAlias result = new VaultAlias();
        result.engineType = defaultEngineType;
        result.mountPath = defaultMountPath;

        String remaining = alias;

        // 1. Extract engine type (optional, starts with "engine=")
        if (remaining.startsWith("engine=")) {
            int nextDelim = findNextDelimiter(remaining, 7, '@', '#');
            if (nextDelim == -1) {
                throw ROOT_LOGGER.invalidEngineSpecificationMissingDelimiter(alias);
            }
            result.engineType = remaining.substring(7, nextDelim);
            if (result.engineType.isEmpty()) {
                throw ROOT_LOGGER.engineTypeCannotBeEmpty(alias);
            }
            remaining = remaining.substring(nextDelim);
        }

        // 2. Extract mount path (optional, starts with @)
        if (remaining.startsWith("@")) {
            int hashPos = remaining.indexOf('#');
            if (hashPos == -1) {
                throw ROOT_LOGGER.missingHashDelimiterAfterMountPath(alias);
            }
            result.mountPath = remaining.substring(1, hashPos);
            if (result.mountPath.isEmpty()) {
                throw ROOT_LOGGER.mountPathCannotBeEmpty(alias);
            }
            remaining = remaining.substring(hashPos);
        }

        // 3. Extract secret path (required, starts with #)
        if (!remaining.startsWith("#")) {
            throw ROOT_LOGGER.secretPathMustStartWithHash(alias);
        }
        remaining = remaining.substring(1); // Skip #

        // 4. Find key delimiter (?)
        int questionPos = remaining.indexOf('?');
        if (questionPos == -1) {
            throw ROOT_LOGGER.missingQuestionDelimiterBeforeKeyPath(alias);
        }

        result.secretPath = remaining.substring(0, questionPos);
        result.keyPath = remaining.substring(questionPos + 1);

        // 5. Validate
        if (result.secretPath.isEmpty()) {
            throw ROOT_LOGGER.secretPathCannotBeEmpty(alias);
        }
        if (result.keyPath.isEmpty()) {
            throw ROOT_LOGGER.keyPathCannotBeEmpty(alias);
        }

        // 6. URL-decode each segment separately
        // CRITICAL: Decode AFTER splitting to avoid double-encoding issues
        result.engineType = urlDecode(result.engineType);
        result.mountPath = urlDecode(result.mountPath);
        result.secretPath = urlDecode(result.secretPath);
        result.keyPath = urlDecode(result.keyPath);

        // Note: The decoded values will be passed to Vault client library,
        // which will handle URL encoding for the actual API calls

        return result;
    }

    /**
     * Find the position of the next delimiter character in the string.
     *
     * @param s the string to search
     * @param start the starting position
     * @param delims the delimiter characters to search for
     * @return the position of the first delimiter found, or -1 if none found
     */
    private static int findNextDelimiter(String s, int start, char... delims) {
        int minPos = -1;
        for (char delim : delims) {
            int pos = s.indexOf(delim, start);
            if (pos != -1 && (minPos == -1 || pos < minPos)) {
                minPos = pos;
            }
        }
        return minPos;
    }

    /**
     * URL-decode a string using UTF-8 encoding.
     *
     * @param s the string to decode
     * @return the decoded string, or the original string if decoding fails
     */
    private static String urlDecode(String s) {
        if (s == null) {
            return null;
        }
        try {
            return URLDecoder.decode(s, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            // UTF-8 should always be supported, but if not, return as-is
            return s;
        } catch (IllegalArgumentException e) {
            // Invalid URL encoding - return as-is
            return s;
        }
    }

    /**
     * Get the engine type (e.g., "KVv1", "KVv2").
     *
     * @return the engine type
     */
    public String getEngineType() {
        return engineType;
    }

    /**
     * Get the mount path (e.g., "secret", "team/backend").
     *
     * @return the mount path
     */
    public String getMountPath() {
        return mountPath;
    }

    /**
     * Get the secret path (e.g., "myapp/database", "my.app.config").
     *
     * @return the secret path
     */
    public String getSecretPath() {
        return secretPath;
    }

    /**
     * Get the key path (e.g., "password", "database/credentials/password").
     *
     * @return the key path
     */
    public String getKeyPath() {
        return keyPath;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("VaultAlias{");
        sb.append("engineType='").append(engineType).append('\'');
        sb.append(", mountPath='").append(mountPath).append('\'');
        sb.append(", secretPath='").append(secretPath).append('\'');
        sb.append(", keyPath='").append(keyPath).append('\'');
        sb.append('}');
        return sb.toString();
    }
}
