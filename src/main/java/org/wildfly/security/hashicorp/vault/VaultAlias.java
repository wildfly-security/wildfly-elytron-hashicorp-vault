/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.wildfly.security.hashicorp.vault._private.HashiCorpVaultLogger.ROOT_LOGGER;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import org.wildfly.security.credential.store.CredentialStoreException;

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

    private final String engineType;
    private final String mountPath;
    private final String secretPath;
    private final String keyPath;


    /**
     * Private constructor - use factory methods to create instances.
     *
     * @param engineType the engine type (KVv1 or KVv2)
     * @param mountPath the mount path
     * @param secretPath the secret path
     * @param keyPath the key path
     */
    private VaultAlias(String engineType, String mountPath, String secretPath, String keyPath) {
        this.engineType = engineType;
        this.mountPath = mountPath;
        this.secretPath = secretPath;
        this.keyPath = keyPath;
    }

    /**
     * Create a VaultAlias directly from components without parsing.
     * This method validates the engine type but does not perform URL encoding -
     * components should already be in their decoded form.
     *
     * @param engineType the engine type (KVv1 or KVv2)
     * @param mountPath the mount path
     * @param secretPath the secret path
     * @param keyPath the key path
     * @return a new VaultAlias instance
     * @throws CredentialStoreException if the engine type is invalid or any required component is null/empty
     */
    static VaultAlias create(String engineType, String mountPath, String secretPath, String keyPath) throws CredentialStoreException {
        // Validate required parameters
        if (engineType == null || engineType.isEmpty()) {
            throw ROOT_LOGGER.engineTypeCannotBeEmpty("direct creation");
        }
        if (mountPath == null || mountPath.isEmpty()) {
            throw ROOT_LOGGER.mountPathCannotBeEmpty("direct creation");
        }
        if (secretPath == null || secretPath.isEmpty()) {
            throw ROOT_LOGGER.secretPathCannotBeEmpty("direct creation");
        }
        if (keyPath == null || keyPath.isEmpty()) {
            throw ROOT_LOGGER.keyPathCannotBeEmpty("direct creation");
        }

        // Validate engine type
        if (!engineType.equals("KVv1") && !engineType.equals("KVv2")) {
            throw ROOT_LOGGER.invalidEngineType(engineType);
        }

        // Validate key path doesn't contain empty segments (if using nested path syntax)
        if (keyPath.contains("/")) {
            if (keyPath.startsWith("/") || keyPath.endsWith("/") || keyPath.contains("//")) {
                throw ROOT_LOGGER.keyPathContainsEmptySegment(keyPath);
            }
        }

        return new VaultAlias(engineType, mountPath, secretPath, keyPath);
    }

    /**
     * Parse a vault alias string using default engine type and mount path.
     *
     * @param alias the alias string to parse
     * @return the parsed VaultAlias
     * @throws CredentialStoreException if the alias format is invalid
     */
    public static VaultAlias parse(String alias) throws CredentialStoreException {
        return parse(alias, "KVv2", "secret");
    }

    /**
     * Parse a vault alias string with legacy format support.
     * <p>
     * This method first checks if the alias uses the new format (contains {@code ?}, {@code #}, {@code @},
     * or starts with {@code engine=}). If so, it delegates to {@link #parse(String, String, String)}.
     * <p>
     * If the alias appears to be in legacy format (no new format indicators), behavior depends on the
     * {@code supportLegacyFormat} parameter:
     * <ul>
     *   <li>If {@code true}: Parse as legacy format (split on last dot) and log deprecation warning</li>
     *   <li>If {@code false}: Throw exception with migration guidance</li>
     * </ul>
     * <p>
     * Legacy format: {@code secret-path.key} where the last dot separates secret path from key.
     *
     * @param alias the alias string to parse
     * @param defaultEngineType the default engine type to use if not specified in alias
     * @param defaultMountPath the default mount path to use if not specified in alias
     * @param supportLegacyFormat whether to support legacy format
     * @return the parsed VaultAlias
     * @throws CredentialStoreException if the alias format is invalid or legacy format is not supported
     */
    public static VaultAlias parseWithLegacySupport(String alias, String defaultEngineType,
                                                     String defaultMountPath, boolean supportLegacyFormat) throws CredentialStoreException {
        if (alias == null || alias.isEmpty()) {
            throw ROOT_LOGGER.aliasCannotBeNullOrEmpty();
        }

        // Check if it's new format (contains ?, #, @, or starts with engine=)
        if (alias.contains("?") || alias.contains("#") ||
            alias.contains("@") || alias.startsWith("engine=")) {
            // New format - use standard parsing
            return parse(alias, defaultEngineType, defaultMountPath);
        }

        // No new format indicators found - check if it's valid legacy format
        int lastDot = alias.lastIndexOf('.');
        if (lastDot == -1) {
            // No dot found - not valid legacy format either
            // This is an invalid alias format
            throw ROOT_LOGGER.invalidAliasFormat(alias);
        }

        // Valid legacy format detected (has a dot)
        if (!supportLegacyFormat) {
            // Legacy format not supported - throw error with migration guidance
            String newFormat = convertLegacyToNewFormat(alias);
            throw ROOT_LOGGER.legacyAliasFormatNotSupported(alias, newFormat);
        }

        // Parse as legacy format and log deprecation warning
        String secretPath = alias.substring(0, lastDot);
        String keyPath = alias.substring(lastDot + 1);

        // Validate
        if (secretPath.isEmpty()) {
            throw ROOT_LOGGER.secretPathCannotBeEmpty(alias);
        }
        if (keyPath.isEmpty()) {
            throw ROOT_LOGGER.keyPathCannotBeEmpty(alias);
        }

        // URL-decode segments (legacy format may also have URL encoding)
        secretPath = urlDecode(secretPath);
        keyPath = urlDecode(keyPath);

        // Log deprecation warning with equivalent new format
        String newFormat = convertLegacyToNewFormat(alias);
        ROOT_LOGGER.legacyAliasFormatDeprecated(alias, newFormat);

        // Create immutable instance
        return new VaultAlias(defaultEngineType, defaultMountPath, secretPath, keyPath);
    }

    /**
     * Convert a legacy format alias to the equivalent new format.
     * <p>
     * Legacy format: {@code secret-path.key} (split on last dot)
     * New format: {@code secret-path?key} (# is optional when no engine= or @ prefix)
     * <p>
     * Note: This method assumes the alias has already been validated to contain a dot.
     *
     * @param legacyAlias the legacy format alias (must contain a dot)
     * @return the equivalent new format alias
     */
    private static String convertLegacyToNewFormat(String legacyAlias) {
        int lastDot = legacyAlias.lastIndexOf('.');
        String secretPath = legacyAlias.substring(0, lastDot);
        String keyPath = legacyAlias.substring(lastDot + 1);
        return secretPath + "?" + keyPath;
    }

    /**
     * Parse a vault alias string with specified defaults for engine type and mount path.
     *
     * @param alias the alias string to parse
     * @param defaultEngineType the default engine type to use if not specified in alias
     * @param defaultMountPath the default mount path to use if not specified in alias
     * @return the parsed VaultAlias
     * @throws CredentialStoreException if the alias format is invalid
     */
    public static VaultAlias parse(String alias, String defaultEngineType, String defaultMountPath) throws CredentialStoreException {
        if (alias == null || alias.isEmpty()) {
            throw ROOT_LOGGER.aliasCannotBeNullOrEmpty();
        }

        ROOT_LOGGER.debugf("Parsing alias: %s", alias);

        // Use local variables to collect parsed values
        String engineType = defaultEngineType;
        String mountPath = defaultMountPath;
        String secretPath;
        String keyPath;

        // Use index-based parsing to reduce GC pressure from intermediate String objects
        int pos = 0;
        final int length = alias.length();

        // 1. Extract engine type (optional, starts with "engine=")
        if (alias.startsWith("engine=")) {
            pos = 7; // Skip "engine="
            int nextDelim = findNextDelimiter(alias, pos, '@', '#');
            if (nextDelim == -1) {
                throw ROOT_LOGGER.invalidEngineSpecificationMissingDelimiter(alias);
            }
            engineType = alias.substring(pos, nextDelim);
            if (engineType.isEmpty()) {
                throw ROOT_LOGGER.engineTypeCannotBeEmpty(alias);
            }
            pos = nextDelim;
        }

        // 2. Extract mount path (optional, starts with @)
        if (pos < length && alias.charAt(pos) == '@') {
            pos++; // Skip @
            int hashPos = alias.indexOf('#', pos);
            if (hashPos == -1) {
                throw ROOT_LOGGER.missingHashDelimiterAfterMountPath(alias);
            }
            mountPath = alias.substring(pos, hashPos);
            if (mountPath.isEmpty()) {
                throw ROOT_LOGGER.mountPathCannotBeEmpty(alias);
            }
            pos = hashPos;
        }

        // 3. Extract secret path (optional # prefix)
        // The # is required only after @ mount path, otherwise it's optional
        if (pos < length && alias.charAt(pos) == '#') {
            pos++; // Skip # if present
        }

        // 4. Find key delimiter (?)
        int questionPos = alias.indexOf('?', pos);
        if (questionPos == -1) {
            throw ROOT_LOGGER.missingQuestionDelimiterBeforeKeyPath(alias);
        }

        secretPath = alias.substring(pos, questionPos);
        keyPath = alias.substring(questionPos + 1);

        // 5. Validate
        if (secretPath.isEmpty()) {
            throw ROOT_LOGGER.secretPathCannotBeEmpty(alias);
        }
        if (keyPath.isEmpty()) {
            throw ROOT_LOGGER.keyPathCannotBeEmpty(alias);
        }

        // 6. URL-decode each segment separately
        // CRITICAL: Decode AFTER splitting to avoid double-encoding issues
        engineType = urlDecode(engineType);
        mountPath = urlDecode(mountPath);
        secretPath = urlDecode(secretPath);
        keyPath = urlDecode(keyPath);

        // 7. Validate key path doesn't contain empty segments (if using nested path syntax)
        if (keyPath.contains("/")) {
            // Check for empty segments: leading /, trailing /, or //
            if (keyPath.startsWith("/") || keyPath.endsWith("/") || keyPath.contains("//")) {
                throw ROOT_LOGGER.keyPathContainsEmptySegment(keyPath);
            }
        }

        // 8. Validate engine type after URL decoding (in case someone URL-encodes the engine type)
        if (!engineType.equals("KVv1") && !engineType.equals("KVv2")) {
            throw ROOT_LOGGER.invalidEngineType(engineType);
        }

        // Note: The decoded values will be passed to Vault client library,
        // which will handle URL encoding for the actual API calls

        ROOT_LOGGER.debugf("Parsed alias: engine=%s, mount=%s, secret=%s, key=%s",
                          engineType, mountPath, secretPath, keyPath);

        // Create immutable instance with all validated values
        return new VaultAlias(engineType, mountPath, secretPath, keyPath);
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

    /**
     * Convert the engine type string to a KV version number.
     *
     * @return 1 for KVv1, 2 for KVv2
     * @throws CredentialStoreException if the engine type is not a valid KV version
     */
    public int getKvVersion() throws CredentialStoreException {
        return engineTypeToVersion(engineType);
    }

    /**
     * Convert an engine type string to a KV version number.
     * This is a utility method that can be used without creating a VaultAlias instance.
     *
     * @param engineType the engine type string (e.g., "KVv1", "KVv2")
     * @return 1 for KVv1, 2 for KVv2
     * @throws CredentialStoreException if the engine type is not a valid KV version
     */
    static int engineTypeToVersion(String engineType) throws CredentialStoreException {
        if (engineType == null) {
            throw ROOT_LOGGER.invalidEngineType("null");
        }
        switch (engineType) {
            case "KVv1":
                return 1;
            case "KVv2":
                return 2;
            default:
                throw ROOT_LOGGER.invalidEngineType(engineType);
        }
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
