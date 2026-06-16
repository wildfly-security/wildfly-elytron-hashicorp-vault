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

    private final String vaultUrl;
    private final String token;
    private final String namespace;
    private final SslConfig sslConfig;
    private Vault vault;
    private final SSLContext sslContext;

    private JwtConfig jwtConfig;

    public VaultConnector(String vaultUrl, String token, String namespace, SslConfig sslConfig, boolean sslVerify) {
        this(vaultUrl, token, namespace, sslConfig, sslVerify, null);
    }

    public VaultConnector(String vaultUrl, String token, String namespace, SslConfig sslConfig, boolean sslVerify, SSLContext sslContext) {
        this.vaultUrl = vaultUrl;
        this.token = token;
        this.namespace = namespace;
        this.sslConfig = sslConfig;
        this.sslContext = sslContext;
    }

    public VaultConnector(String vaultUrl, JwtConfig jwtConfig, String namespace, SslConfig sslConfig) {
        this(vaultUrl, jwtConfig, namespace, sslConfig, null);
    }

    public VaultConnector(String vaultUrl, JwtConfig jwtConfig, String namespace, SslConfig sslConfig, SSLContext sslContext) {
        this.vaultUrl = vaultUrl;
        this.token = null;
        this.namespace = namespace;
        this.sslConfig = sslConfig;
        this.jwtConfig = jwtConfig;
        this.sslContext = sslContext;
    }

    public void configure() throws VaultException {
        try {

            VaultConfig config = new VaultConfig()
                    .sslConfig(this.sslConfig)
                    .address(this.vaultUrl);
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
            this.vault = tryLoginWithFallback(loginContext, config);

            ROOT_LOGGER.vaultConfigurationSuccessful(this.vaultUrl);
        } catch (VaultException e) {
            ROOT_LOGGER.vaultConnectorConfigurationFailed(this.vaultUrl, e);
            throw e;
        }
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
     * Retrieve a secret from Vault
     */
    public String getSecret(String path, String key) throws VaultException {
        if (path == null || path.trim().isEmpty()) {
            throw new VaultException(ROOT_LOGGER.vaultPathCannotBeNullOrEmpty());
        }
        if (key == null || key.trim().isEmpty()) {
            throw new VaultException(ROOT_LOGGER.vaultKeyCannotBeNullOrEmpty());
        }

        // Fetch from Vault
        LogicalResponse response = this.vault.logical().read(path);
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

        Map<String, Object> nameValuePairs = new HashMap<>();
        // Read existing path to preserve other keys if those exist
        LogicalResponse readResponse = this.vault.logical().read(path);
        int readStatus = readResponse.getRestResponse().getStatus();
        if (readStatus == 200) {
            Map<String, String> existingData = readResponse.getData();
            if (existingData != null) {
                nameValuePairs.putAll(existingData);
            }
        }

        nameValuePairs.put(key, value);
        LogicalResponse response = this.vault.logical().write(path, nameValuePairs);
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

        // Read existing path to preserve other keys at the same path
        Map<String, Object> nameValuePairs = new HashMap<>();
        LogicalResponse readResponse = this.vault.logical().read(path);
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
            LogicalResponse deleteResponse = this.vault.logical().delete(path);
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
            LogicalResponse writeResponse = this.vault.logical().write(path, nameValuePairs);
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
        LogicalResponse response = this.vault.logical().read(path);
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
        // vault expects trailing slash with list operation
        String listPath = path.endsWith("/") ? path : path + "/";

        try {
            LogicalResponse response = this.vault.logical().list(listPath);
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
