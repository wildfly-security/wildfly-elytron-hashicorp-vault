/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.wildfly.security.hashicorp.vault._private.HashiCorpVaultLogger.ROOT_LOGGER;

import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

import javax.net.ssl.SSLContext;

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
    private Vault vaultV2;  // Default Vault instance configured for KV v2
    private Vault vaultV1;  // Vault instance configured for KV v1 (created lazily if needed)
    private final SSLContext sslContext;
    private final Predicate<String> kvV1FallbackPredicate;

    private JwtConfig jwtConfig;

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
        this.sslContext = sslContext;
        this.kvV1FallbackPredicate = kvV1FallbackPredicate != null ? kvV1FallbackPredicate : DEFAULT_KV_V1_FALLBACK_PREDICATE;
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
        this.sslContext = sslContext;
        this.kvV1FallbackPredicate = kvV1FallbackPredicate != null ? kvV1FallbackPredicate : DEFAULT_KV_V1_FALLBACK_PREDICATE;
    }

    public void configure() throws VaultException {
        // Both Vault instances will be created lazily on first use
        // This avoids unnecessary overhead if only one version is needed
        this.vaultV1 = null;
        this.vaultV2 = null;

        ROOT_LOGGER.vaultConfigurationSuccessful(this.vaultUrl);
    }

    /**
     * Login with subsequently with each possible method and stop when login was successful. Resulting Vault will carry
     * VaultConfig with token which obtained from the final login attempt.
     * Note that only methods which prerequisites are satisfied will be tried.
     * @param loginContext current login context
     * @param config initial VaultConfig
     * @return Vault with token configured
     * @throws VaultException thrown when anything goes wrong, including situation when all methods fail.
     */
    private Vault tryLoginWithFallback(LoginContext loginContext, VaultConfig config) throws VaultException {
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

        throw new VaultException(ROOT_LOGGER.vaultAllLoginStrategiesFailed());
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
     * Get the appropriate Vault instance based on the path and KV version predicate.
     * Creates Vault instances lazily on first use.
     */
    private synchronized Vault getVaultForPath(String path) throws VaultException {
        String rootPath = extractRootPath(path);

        if (kvV1FallbackPredicate.test(rootPath)) {
            // Need KV v1 - create instance if not already created
            if (vaultV1 == null) {
                vaultV1 = createVaultInstance(1);
            }
            return vaultV1;
        }

        // Default to KV v2 - create instance if not already created
        if (vaultV2 == null) {
            vaultV2 = createVaultInstance(2);
        }
        return vaultV2;
    }

    /**
     * Create a Vault instance configured for the specified KV engine version.
     */
    private Vault createVaultInstance(int kvVersion) throws VaultException {
        VaultConfig config = new VaultConfig()
                .sslConfig(this.sslConfig)
                .address(this.vaultUrl)
                .engineVersion(kvVersion);

        HttpClient httpClient;
        if (sslContext != null) {
            httpClient = HttpClient.newBuilder()
                    .sslContext(sslContext)
                    .build();
            config.httpClient(httpClient);
        }

        if (this.namespace != null && !this.namespace.isEmpty()) {
            config.nameSpace(this.namespace);
        }

        final LoginContext loginContext = new LoginContext(token, jwtConfig,
                Vault.create(config.build()));
        return tryLoginWithFallback(loginContext, config);
    }

    /**
     * Extract the root path (mount point) from a full path.
     * For example: "secret/myapp/db" -> "secret"
     */
    private String extractRootPath(String path) {
        if (path == null || path.isEmpty()) {
            return "";
        }
        int slashIndex = path.indexOf('/');
        if (slashIndex == -1) {
            return path;
        }
        return path.substring(0, slashIndex);
    }

    /**
     * Retrieve a secret from Vault
     */
    public String getSecret(String path, String key) throws VaultException {
        if (path == null || path.trim().isEmpty()) {
            throw new VaultException(ROOT_LOGGER.vaultPathCannotBeNullOrEmpty());
        }
        if (key == null || key.trim().isEmpty()) {
            throw new VaultException(ROOT_LOGGER.vaultKeyCannotBeNullOrEmpty());
        }

        // Get the appropriate Vault instance for this path
        Vault vault = getVaultForPath(path);

        // Fetch from Vault - the library handles path adjustments internally
        LogicalResponse response = vault.logical().read(path);
        int responseStatus = response.getRestResponse().getStatus();
        if (responseStatus == 200) {
            Map<String, String> data = response.getData();
            String value = data.get(key);
            if (value != null) {
                ROOT_LOGGER.vaultRetrievedSecret(path, this.vaultUrl);
            } else {
                ROOT_LOGGER.vaultKeyNotFoundInSecret(key, path);
            }
            return value;
        }
        if (responseStatus == 403) {
            ROOT_LOGGER.vaultForbiddenToRetrieveSecret(path);
            throw new VaultException(ROOT_LOGGER.vaultForbiddenToRetrieveSecretAtPath(path));
        }
        if (responseStatus == 404) {
            ROOT_LOGGER.vaultSecretNotFoundAtPath(path);
            return null;
        }

        throw new VaultException(ROOT_LOGGER.vaultFailedToRetrieveSecretHttp(path, key, responseStatus));
    }

    /**
     * Store a secret in Vault
     */
    public void putSecret(String path, String key, String value) throws VaultException {
        if (path == null || path.trim().isEmpty()) {
            throw new VaultException(ROOT_LOGGER.vaultPathCannotBeNullOrEmpty());
        }
        if (key == null || key.trim().isEmpty()) {
            throw new VaultException(ROOT_LOGGER.vaultKeyCannotBeNullOrEmpty());
        }
        if (value == null) {
            throw new VaultException(ROOT_LOGGER.vaultValueCannotBeNull());
        }

        // Get the appropriate Vault instance for this path
        Vault vault = getVaultForPath(path);

        Map<String, Object> nameValuePairs = new HashMap<>();
        // Read existing path to preserve other keys if those exist
        LogicalResponse readResponse = vault.logical().read(path);
        int readStatus = readResponse.getRestResponse().getStatus();
        if (readStatus == 200) {
            Map<String, String> existingData = readResponse.getData();
            if (existingData != null) {
                nameValuePairs.putAll(existingData);
            }
        }

        nameValuePairs.put(key, value);
        LogicalResponse response = vault.logical().write(path, nameValuePairs);
        int responseStatus = response.getRestResponse().getStatus();
        if (responseStatus == 200 || responseStatus == 204) {
            ROOT_LOGGER.vaultStoredSecret(path, this.vaultUrl);
            return;
        }
        if (responseStatus == 403) {
            throw new VaultException(ROOT_LOGGER.vaultForbiddenToStoreSecretAtPath(path));
        }

        throw new VaultException(ROOT_LOGGER.vaultFailedToStoreSecretHttp(path, key, responseStatus));
    }

    /**
     * Remove a secret from Vault
     */
    public void removeSecret(String path, String key) throws VaultException {
        if (path == null || path.trim().isEmpty()) {
            throw new VaultException(ROOT_LOGGER.vaultPathCannotBeNullOrEmpty());
        }
        if (key == null || key.trim().isEmpty()) {
            throw new VaultException(ROOT_LOGGER.vaultKeyCannotBeNullOrEmpty());
        }

        // Get the appropriate Vault instance for this path
        Vault vault = getVaultForPath(path);

        // Read existing path to preserve other keys at the same path
        Map<String, Object> nameValuePairs = new HashMap<>();
        LogicalResponse readResponse = vault.logical().read(path);
        int readStatus = readResponse.getRestResponse().getStatus();
        if (readStatus == 200) {
            Map<String, String> existingData = readResponse.getData();
            if (existingData != null) {
                nameValuePairs.putAll(existingData);
            }
        }

        if (!nameValuePairs.containsKey(key)) {
            ROOT_LOGGER.vaultKeyDoesNotExistAtPath(key, path);
            return;
        }
        nameValuePairs.remove(key);
        if (nameValuePairs.isEmpty()) {
            LogicalResponse deleteResponse = vault.logical().delete(path);
            int deleteStatus = deleteResponse.getRestResponse().getStatus();
            if (deleteStatus == 200 || deleteStatus == 204) {
                ROOT_LOGGER.vaultDeletedSecretPath(path);
                return;
            }
            if (deleteStatus == 403) {
                throw new VaultException(ROOT_LOGGER.vaultForbiddenToDeleteSecretAtPath(path));
            }
            throw new VaultException(ROOT_LOGGER.vaultFailedToDeleteSecretHttp(path, deleteStatus));
        } else {
            // Write back the remaining keys
            LogicalResponse writeResponse = vault.logical().write(path, nameValuePairs);
            int writeStatus = writeResponse.getRestResponse().getStatus();
            if (writeStatus == 200 || writeStatus == 204) {
                ROOT_LOGGER.vaultRemovedKeyFromPath(key, path);
                return;
            }
            if (writeStatus == 403) {
                throw new VaultException(ROOT_LOGGER.vaultForbiddenToUpdateSecretAtPath(path));
            }
            throw new VaultException(ROOT_LOGGER.vaultFailedToUpdateSecretAfterRemoveKey(path, key, writeStatus));
        }
    }

    /**
     * Get all keys for a specific path
     */
    public Set<String> getKeysForPath(String path) throws VaultException {
        Vault vault = getVaultForPath(path);
        LogicalResponse response = vault.logical().read(path);
        int responseStatus = response.getRestResponse().getStatus();
        if (responseStatus == 200) {
            Map<String, String> data = response.getData();
            if (data != null && !data.isEmpty()) {
                return new HashSet<>(data.keySet());
            }
            return new HashSet<>();
        } else if (responseStatus == 404) {
            throw new VaultException(ROOT_LOGGER.vaultPathDoesNotExistOrForbidden(path));
        } else {
            throw new VaultException(ROOT_LOGGER.vaultFailedToReadAliasesOnPath(path));
        }
    }

    /**
     * Get a set of all items at a given path (without the parent path prefix)
     */
    public Set<String> listAllItemsAtPath(String path) throws VaultException {
        if (path == null || path.trim().isEmpty()) {
            throw new VaultException(ROOT_LOGGER.vaultPathCannotBeNullOrEmpty());
        }

        // Get the appropriate Vault instance for this path
        Vault vault = getVaultForPath(path);

        // vault expects trailing slash with list operation
        String listPath = path.endsWith("/") ? path : path + "/";

        try {
            LogicalResponse response = vault.logical().list(listPath);
            int responseStatus = response.getRestResponse().getStatus();
            if (responseStatus == 200) {
                List<String> keys = response.getListData();
                if (keys != null && !keys.isEmpty()) {
                    return new HashSet<>(keys);
                }
                return new HashSet<>();
            } else if (responseStatus == 404) {
                throw new VaultException(ROOT_LOGGER.vaultPathNotFoundInVault(path));
            } else if (responseStatus == 403) {
                throw new VaultException(ROOT_LOGGER.vaultForbiddenToListSubpathsAtPath(path));
            } else {
                throw new VaultException(ROOT_LOGGER.vaultFailedToListSubpathsHttp(path, responseStatus));
            }
        } catch (ClassCastException e) {
            throw new VaultException(ROOT_LOGGER.vaultUnexpectedListSubpathsFormat(path, e.getMessage()));
        }
    }

}
