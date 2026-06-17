/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.wildfly.security.hashicorp.vault._private.HashiCorpVaultLogger.ROOT_LOGGER;

import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

import javax.net.ssl.SSLContext;

import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.hashicorp.vault.loginstrategy.ClientCertificateLoginStrategy;
import org.wildfly.security.hashicorp.vault.loginstrategy.JwtLoginStrategy;
import org.wildfly.security.hashicorp.vault.loginstrategy.LoginContext;
import org.wildfly.security.hashicorp.vault.loginstrategy.TokenLoginStrategy;
import org.wildfly.security.hashicorp.vault.loginstrategy.VaultLoginStrategy;

import io.github.jopenlibs.vault.SslConfig;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.response.LogicalResponse;

/**
 * Vault Connector
 */
class VaultConnector {

    private static final Predicate<String> DEFAULT_KV_V1_FALLBACK_PREDICATE = path -> false;

    private final String vaultUrl;
    private final String token;
    private final String namespace;
    private final SslConfig sslConfig;

    /**
     * Cached HttpClient instance (created once during initialization).
     * Reused across all Vault instances for efficient connection pooling.
     * HttpClient in Java 11+ uses connection pooling by default, so a single
     * instance can efficiently handle multiple concurrent requests to the same destination.
     */
    private final HttpClient httpClient;

    private JwtConfig jwtConfig;

    /**
     * Cache of Vault instances keyed by engine type and mount path segment count.
     * Key format: "KVv1" or "KVv2-{segmentCount}"
     * For KV v1, segment count doesn't matter (no /data/ insertion)
     * For KV v2, we need different instances for different segment counts
     */
    private final Map<String, Vault> vaultInstanceCache = new HashMap<>();

    public VaultConnector(String vaultUrl, String token, String namespace, SslConfig sslConfig, boolean sslVerify) {
        this(vaultUrl, token, namespace, sslConfig, sslVerify, null, DEFAULT_KV_V1_FALLBACK_PREDICATE);
    }

    public VaultConnector(String vaultUrl, String token, String namespace, SslConfig sslConfig, boolean sslVerify, SSLContext sslContext) {
        this(vaultUrl, token, namespace, sslConfig, sslVerify, sslContext, DEFAULT_KV_V1_FALLBACK_PREDICATE);
    }

    public VaultConnector(String vaultUrl, String token, String namespace, SslConfig sslConfig, boolean sslVerify, SSLContext sslContext, Predicate<String> kvV1FallbackPredicate) {
        this.vaultUrl = vaultUrl;
        this.token = token;
        this.namespace = namespace;
        this.sslConfig = sslConfig;

        // Always create HttpClient for connection pooling efficiency
        // HttpClient in Java 11+ uses connection pooling by default
        HttpClient.Builder builder = HttpClient.newBuilder();
        if (sslContext != null) {
            builder.sslContext(sslContext);
        }
        this.httpClient = builder.build();
    }

    public VaultConnector(String vaultUrl, JwtConfig jwtConfig, String namespace, SslConfig sslConfig) {
        this(vaultUrl, jwtConfig, namespace, sslConfig, null, DEFAULT_KV_V1_FALLBACK_PREDICATE);
    }

    public VaultConnector(String vaultUrl, JwtConfig jwtConfig, String namespace, SslConfig sslConfig, SSLContext sslContext) {
        this(vaultUrl, jwtConfig, namespace, sslConfig, sslContext, DEFAULT_KV_V1_FALLBACK_PREDICATE);
    }

    public VaultConnector(String vaultUrl, JwtConfig jwtConfig, String namespace, SslConfig sslConfig, SSLContext sslContext, Predicate<String> kvV1FallbackPredicate) {
        this.vaultUrl = vaultUrl;
        this.token = null;
        this.namespace = namespace;
        this.sslConfig = sslConfig;
        this.jwtConfig = jwtConfig;

        // Always create HttpClient for connection pooling efficiency
        // HttpClient in Java 11+ uses connection pooling by default
        HttpClient.Builder builder = HttpClient.newBuilder();
        if (sslContext != null) {
            builder.sslContext(sslContext);
        }
        this.httpClient = builder.build();
    }

    public void configure() {
        // Vault instances will be created lazily on first use and cached
        ROOT_LOGGER.vaultConfigurationSuccessful(this.vaultUrl);
    }

    /**
     * Login with subsequently with each possible method and stop when login was successful. Resulting Vault will carry
     * VaultConfig with token which obtained from the final login attempt.
     * Note that only methods which prerequisites are satisfied will be tried.
     * @param loginContext current login context
     * @param config initial VaultConfig
     * @return Vault with token configured
     * @throws CredentialStoreException thrown when all login strategies fail
     */
    private Vault tryLoginWithFallback(LoginContext loginContext, VaultConfig config) throws CredentialStoreException {
        for (VaultLoginStrategy strategy : composePossibleLoginStrategiesPrioritized(loginContext)) {
            try {
                String response = strategy.tryLogin(loginContext);

                if (response != null) {
                    config.token(response);
                    Vault vault = Vault.create(config.build());
                    //test that token can be used to perform anything requiring authentication
                    vault.auth().lookupSelf();
                    return vault;
                }
            } catch (VaultException e) {
                ROOT_LOGGER.vaultLoginAttemptFailed(strategy.getClass().getSimpleName(), e);
            }
        }

        throw ROOT_LOGGER.vaultAllLoginStrategiesFailed();
    }

    private List<VaultLoginStrategy> composePossibleLoginStrategiesPrioritized(final LoginContext loginContext) {
        final List<VaultLoginStrategy> loginStrategies = new ArrayList<>();
        if (!hasNonEmptyToken(loginContext)) {
            loginStrategies.add(new ClientCertificateLoginStrategy());
        }
        if (loginContext.getJwtConfig() != null) {
            loginStrategies.add(new JwtLoginStrategy());
        }
        if (loginContext.getToken() != null) {
            loginStrategies.add(new TokenLoginStrategy());
        }
        return loginStrategies;
    }

    private static boolean hasNonEmptyToken(final LoginContext loginContext) {
        final String t = loginContext.getToken();
        return t != null && !t.trim().isEmpty();
    }

    /**
     * Count the number of path segments in a mount path.
     * For example: "secret" = 1, "team/backend" = 2, "org/team/backend" = 3
     *
     * @param mountPath the mount path
     * @return the number of segments
     */
    private int countMountPathSegments(String mountPath) {
        if (mountPath == null || mountPath.isEmpty()) {
            return 0;
        }
        // Count slashes and add 1
        int count = 1;
        for (int i = 0; i < mountPath.length(); i++) {
            if (mountPath.charAt(i) == '/') {
                count++;
            }
        }
        return count;
    }

    /**
     * Get the appropriate Vault instance based on the alias engine type and mount path.
     * Creates Vault instances lazily on first use and caches them.
     *
     * For KV v2, different mount path segment counts require different Vault instances
     * because the driver needs to know where to insert the /data/ segment.
     *
     * @param alias the parsed vault alias containing engine type and path information
     * @return the appropriate Vault instance for the specified engine type and mount path
     */
    private synchronized Vault getVaultForAlias(VaultAlias alias) {
        String engineType = alias.getEngineType();
        String mountPath = alias.getMountPath();

        // Determine KV version and segment count
        final int kvVersion;
        final int segmentCount;
        final String cacheKey;

        if ("KVv1".equals(engineType)) {
            // KV v1 doesn't use /data/ insertion, so segment count doesn't matter
            kvVersion = 1;
            segmentCount = 0; // irrelevant for v1
            cacheKey = "KVv1";
        } else {
            // KV v2 - need to account for mount path segment count
            kvVersion = 2;
            segmentCount = countMountPathSegments(mountPath);
            cacheKey = "KVv2-" + segmentCount;
        }

        return vaultInstanceCache.computeIfAbsent(cacheKey,
            k -> {
                try {
                    return createVaultInstance(kvVersion, segmentCount);
                } catch (VaultException | CredentialStoreException e) {
                    throw new RuntimeException(e);
                }
            });
    }


    /**
     * Create a Vault instance configured for the specified KV engine version and mount path depth.
     *
     * @param kvVersion the KV engine version (1 or 2)
     * @param prefixPathDepth the number of path segments in the mount path (e.g., "secret" = 1, "team/backend" = 2)
     * @return configured Vault instance
     * @throws VaultException if Vault library operations fail
     * @throws CredentialStoreException if login fails
     */
    private Vault createVaultInstance(int kvVersion, int prefixPathDepth) throws VaultException, CredentialStoreException {
        VaultConfig config = new VaultConfig()
                .sslConfig(this.sslConfig)
                .address(this.vaultUrl)
                .engineVersion(kvVersion)
                .prefixPathDepth(prefixPathDepth);

        // Always use the shared HttpClient for connection pooling
        config.httpClient(httpClient);

        if (this.namespace != null && !this.namespace.isEmpty()) {
            config.nameSpace(this.namespace);
        }

        final LoginContext loginContext = new LoginContext(token, jwtConfig,
                Vault.create(config.build()));
        return tryLoginWithFallback(loginContext, config);
    }

    /**
     * Construct the full Vault path from alias components.
     * Combines mount path and secret path with proper formatting.
     *
     * @param alias the parsed vault alias
     * @return the full path for Vault API calls
     */
    private String constructVaultPath(VaultAlias alias) {
        String mountPath = alias.getMountPath();
        String secretPath = alias.getSecretPath();

        // Ensure mount path doesn't end with /
        if (mountPath.endsWith("/")) {
            mountPath = mountPath.substring(0, mountPath.length() - 1);
        }

        // Ensure secret path doesn't start with /
        if (secretPath.startsWith("/")) {
            secretPath = secretPath.substring(1);
        }

        return mountPath + "/" + secretPath;
    }

    /**
     * Retrieve full secret data from Vault using the new alias format.
     * Returns the complete data map for the secret, which can then be
     * processed using KeyPathResolver to extract specific values.
     *
     * @param alias the parsed vault alias containing mount path, secret path, and engine type
     * @return map of all key-value pairs in the secret, or null if secret not found
     * @throws CredentialStoreException if retrieval fails
     */
    public Map<String, Object> getSecretData(VaultAlias alias) throws CredentialStoreException {
        if (alias == null) {
            throw ROOT_LOGGER.vaultAliasCannotBeNull();
        }

        String path = constructVaultPath(alias);

        try {
            // Get the appropriate Vault instance based on alias engine type
            Vault vault = getVaultForAlias(alias);

            // Fetch from Vault - the library handles path adjustments internally
            LogicalResponse response = vault.logical().read(path);
            int responseStatus = response.getRestResponse().getStatus();
            if (responseStatus == 200) {
                Map<String, String> data = response.getData();
                if (data != null) {
                    ROOT_LOGGER.vaultRetrievedSecret(path, this.vaultUrl);
                    // Convert Map<String, String> to Map<String, Object> for KeyPathResolver
                    Map<String, Object> result = new HashMap<>();
                    result.putAll(data);
                    return result;
                }
                return null;
            }
            if (responseStatus == 403) {
                ROOT_LOGGER.vaultForbiddenToRetrieveSecret(path);
                throw ROOT_LOGGER.vaultForbiddenToRetrieveSecretAtPath(path);
            }
            if (responseStatus == 404) {
                ROOT_LOGGER.vaultSecretNotFoundAtPath(path);
                return null;
            }

            throw ROOT_LOGGER.vaultFailedToRetrieveSecretHttp(path, alias.getKeyPath(), responseStatus);
        } catch (VaultException e) {
            throw new CredentialStoreException("Failed to retrieve secret from Vault: " + e.getMessage(), e);
        }
    }

    /**
     * Store a secret value in Vault using the new alias format.
     * This method reads the existing secret data, updates the specified key path,
     * and writes the entire secret back to Vault.
     *
     * @param alias the parsed vault alias specifying location and key path
     * @param value the value to store
     * @throws CredentialStoreException if the operation fails
     */
    Map<String, Object> putSecretData(VaultAlias alias, String value) throws CredentialStoreException {
        if (alias == null) {
            throw ROOT_LOGGER.vaultAliasCannotBeNull();
        }
        if (value == null) {
            throw ROOT_LOGGER.vaultValueCannotBeNull();
        }

        String path = constructVaultPath(alias);

        try {
            Vault vault = getVaultForAlias(alias);

            // Read existing secret data to preserve other keys
            Map<String, Object> secretData = new HashMap<>();
            LogicalResponse readResponse = vault.logical().read(path);
            int readStatus = readResponse.getRestResponse().getStatus();
            if (readStatus == 200) {
                Map<String, String> existingData = readResponse.getData();
                if (existingData != null) {
                    secretData.putAll(existingData);
                }
            }

            // Update the value at the specified key path
            String keyPath = alias.getKeyPath();
            if (keyPath.contains("/")) {
                // Nested key path - need to traverse and update
                KeyPathResolver.setNestedValue(secretData, keyPath, value);
            } else {
                // Simple key - direct update
                secretData.put(keyPath, value);
            }

            // Write back to Vault
            LogicalResponse response = vault.logical().write(path, secretData);
            int responseStatus = response.getRestResponse().getStatus();
            if (responseStatus == 200 || responseStatus == 204) {
                ROOT_LOGGER.vaultStoredSecret(path, this.vaultUrl);
                return secretData;
            }
            if (responseStatus == 403) {
                throw ROOT_LOGGER.vaultForbiddenToStoreSecretAtPath(path);
            }

            throw ROOT_LOGGER.vaultFailedToStoreSecretHttp(path, keyPath, responseStatus);
        } catch (VaultException e) {
            throw new CredentialStoreException("Failed to store secret in Vault: " + e.getMessage(), e);
        }
    }

    /**
     * Remove a secret value from Vault using the new alias format.
     * This method reads the existing secret data, removes the specified key path,
     * and either writes the remaining data back or deletes the entire secret if empty.
     *
     * @param alias the parsed vault alias specifying location and key path
     * @throws CredentialStoreException if the operation fails
     */
    void removeSecretData(VaultAlias alias) throws CredentialStoreException {
        if (alias == null) {
            throw ROOT_LOGGER.vaultAliasCannotBeNull();
        }

        String path = constructVaultPath(alias);

        try {
            Vault vault = getVaultForAlias(alias);

            // Read existing secret data
            Map<String, Object> secretData = new HashMap<>();
            LogicalResponse readResponse = vault.logical().read(path);
            int readStatus = readResponse.getRestResponse().getStatus();
            if (readStatus == 200) {
                Map<String, String> existingData = readResponse.getData();
                if (existingData != null) {
                    secretData.putAll(existingData);
                }
            }

            // Remove the value at the specified key path
            String keyPath = alias.getKeyPath();
            boolean removed;
            if (keyPath.contains("/")) {
                // Nested key path - need to traverse and remove
                removed = KeyPathResolver.removeNestedValue(secretData, keyPath);
            } else {
                // Simple key - direct removal
                removed = secretData.remove(keyPath) != null;
            }

            if (!removed) {
                ROOT_LOGGER.vaultKeyDoesNotExistAtPath(keyPath, path);
                return;
            }

            // If secret data is now empty, delete the entire secret
            if (secretData.isEmpty()) {
                LogicalResponse deleteResponse = vault.logical().delete(path);
                int deleteStatus = deleteResponse.getRestResponse().getStatus();
                if (deleteStatus == 200 || deleteStatus == 204) {
                    ROOT_LOGGER.vaultDeletedSecretPath(path);
                    return;
                }
                if (deleteStatus == 403) {
                    throw ROOT_LOGGER.vaultForbiddenToDeleteSecretAtPath(path);
                }
                throw ROOT_LOGGER.vaultFailedToDeleteSecretHttp(path, deleteStatus);
            } else {
                // Write back the remaining keys
                LogicalResponse writeResponse = vault.logical().write(path, secretData);
                int writeStatus = writeResponse.getRestResponse().getStatus();
                if (writeStatus == 200 || writeStatus == 204) {
                    ROOT_LOGGER.vaultRemovedKeyFromPath(keyPath, path);
                    return;
                }
                if (writeStatus == 403) {
                    throw ROOT_LOGGER.vaultForbiddenToUpdateSecretAtPath(path);
                }
                throw ROOT_LOGGER.vaultFailedToUpdateSecretAfterRemoveKey(path, keyPath, writeStatus);
            }
        } catch (VaultException e) {
            throw new CredentialStoreException("Failed to remove secret from Vault: " + e.getMessage(), e);
        }
    }

}
