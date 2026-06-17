/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.wildfly.security.credential.store._private.ElytronMessages.log;
import static org.wildfly.security.hashicorp.vault._private.HashiCorpVaultLogger.ROOT_LOGGER;

import java.io.IOException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

import javax.net.ssl.SSLContext;

import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.CredentialStoreExtension;
import org.wildfly.security.credential.store.CredentialStoreSpi;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;
import org.wildfly.security.password.interfaces.ClearPassword;

import io.github.jopenlibs.vault.SslConfig;

/**
 * Credential store backed by Hashicorp Vault
 */
public class HashicorpVaultCredentialStore extends CredentialStoreSpi {

    private static final int DEFAULT_MAX_ALIASES = 10_000;
    private static final int DEFAULT_MAX_DEPTH = 100;
    /** Default maximum number of credentials to keep in the in-memory cache. */
    private static final int DEFAULT_CREDENTIAL_CACHE_MAX_SIZE = 500;
    private static List<Class<? extends CredentialStoreExtension>> SUPPORTED_EXTENSION_TYPES =
            List.of(HashicorpVaultCredentialStoreExtension.class);
    /** Default predicate that always returns false (use KV v2 for all paths). */
    private static final Predicate<String> DEFAULT_KV_V1_FALLBACK_PREDICATE = path -> false;

    String hostAddress;
    String namespace;
    CredentialStore.ProtectionParameter protectionParameter;
    Provider[] providers;
    VaultConnector vaultConnector;
    private String trustStorePath;
    private String keyStorePath;
    private String keyStorePass;
    private String trustStorePass;
    private SSLContext sslContext;
    private Predicate<String> kvV1FallbackPredicate = DEFAULT_KV_V1_FALLBACK_PREDICATE;

    /** In-memory LRU cache of retrieved credentials, keyed by credential alias (e.g. "path.key"). */
    private Map<String, Credential> credentialCache;

    /** Whether to support legacy alias format (secret-path.key). Defaults to false. */
    private boolean supportLegacyAliasFormat = false;

    /** Default engine type to use when not specified in alias. */
    private String defaultEngineType = "KVv2";

    /** Default mount path to use when not specified in alias. */
    private String defaultMountPath = "secret";


    @Override
    public void initialize(Map<String, String> attributes, CredentialStore.ProtectionParameter protectionParameter, Provider[] providers) throws CredentialStoreException {
        if (attributes == null) {
            throw ROOT_LOGGER.attributesCannotBeNull();
        }

        // Check required attributes
        this.hostAddress = attributes.get("host-address");
        if (this.hostAddress == null || this.hostAddress.trim().isEmpty()) {
            throw ROOT_LOGGER.hostAddressRequired();
        }

        if (attributes.get("trust-store-path") != null) {
            this.trustStorePath = attributes.get("trust-store-path");
        }

        if (attributes.get("key-store-path") != null) {
            this.keyStorePath = attributes.get("key-store-path");
        }

        if (attributes.get("key-store-pass") != null) {
            this.keyStorePass = attributes.get("key-store-pass");
        }

        if (attributes.get("trust-store-pass") != null) {
            this.trustStorePass = attributes.get("trust-store-pass");
        }

        this.namespace = attributes.get("namespace");
        this.protectionParameter = protectionParameter;
        this.providers = providers;

        // Parse new configuration parameters
        if (attributes.get("support-legacy-alias-format") != null) {
            this.supportLegacyAliasFormat = Boolean.parseBoolean(attributes.get("support-legacy-alias-format"));
        }

        if (attributes.get("default-engine-type") != null) {
            this.defaultEngineType = attributes.get("default-engine-type");
            // Validate engine type
            if (!this.defaultEngineType.equals("KVv1") && !this.defaultEngineType.equals("KVv2")) {
                throw ROOT_LOGGER.invalidDefaultEngineType(this.defaultEngineType);
            }
        }

        if (attributes.get("default-mount-path") != null) {
            this.defaultMountPath = attributes.get("default-mount-path");
        }

        this.credentialCache = Collections.synchronizedMap(new LinkedHashMap<String, Credential>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Credential> eldest) {
                return size() > DEFAULT_CREDENTIAL_CACHE_MAX_SIZE;
            }
        });

        try {
            char[] password = getStorePassword(protectionParameter);
            String token = password != null ? String.valueOf(password) : null;
            boolean hasToken = token != null && !token.trim().isEmpty();
            boolean hasClientCertConfig = this.sslContext != null
                    || (this.keyStorePath != null && !this.keyStorePath.trim().isEmpty());
            if (!hasToken && !hasClientCertConfig) {
                throw ROOT_LOGGER.noAuthenticationMethodConfigured();
            }

            SslConfig sslConfig = new SslConfig().verify(true);

            if (this.keyStorePath != null && !this.keyStorePath.trim().isEmpty()) {
                try {
                    KeyStore keyStore = KeyStore.getInstance("JKS");
                    try (java.io.FileInputStream fis = new java.io.FileInputStream(this.keyStorePath)) {
                        keyStore.load(fis, this.keyStorePass != null ? this.keyStorePass.toCharArray() : null);
                    }

                    if (this.keyStorePass != null) {
                        sslConfig.keyStore(keyStore, this.keyStorePass);
                    } else {
                        sslConfig.keyStore(keyStore, "");
                    }
                } catch (Exception e) {
                    throw ROOT_LOGGER.failedToLoadKeyStore(e.getMessage(), e);
                }
            }

            if (this.trustStorePath != null && !this.trustStorePath.trim().isEmpty()) {
                try {
                    KeyStore trustStore = KeyStore.getInstance("JKS");
                    try (java.io.FileInputStream fis = new java.io.FileInputStream(this.trustStorePath)) {
                        trustStore.load(fis, this.trustStorePass != null ? this.trustStorePass.toCharArray() : null);
                    }
                    if (this.trustStorePass != null) {
                        sslConfig.trustStore(trustStore);
                    } else {
                        sslConfig.trustStore(trustStore);
                    }
                } catch (Exception e) {
                    throw ROOT_LOGGER.failedToLoadTrustStore(e.getMessage(), e);
                }
            }

            vaultConnector = new VaultConnector(this.hostAddress, token, this.namespace, sslConfig, true, sslContext, kvV1FallbackPredicate);
            vaultConnector.configure();

            initialized = true;
        } catch (IOException e) {
            throw ROOT_LOGGER.failedToInitializeVaultCredentialStore(e);
        }
    }

    public void setSslContext(SSLContext sslContext) {
        this.sslContext = sslContext;
    }

    public void setKvV1FallbackPredicate(Predicate<String> kvV1FallbackPredicate) {
        this.kvV1FallbackPredicate = kvV1FallbackPredicate != null ? kvV1FallbackPredicate : DEFAULT_KV_V1_FALLBACK_PREDICATE;
    }

    @Override
    public boolean isModifiable() {
        return true;
    }

    @Override
    public void store(String credentialAlias, Credential credential, CredentialStore.ProtectionParameter protectionParameter) throws CredentialStoreException, UnsupportedCredentialTypeException {
        if (!initialized) {
            throw ROOT_LOGGER.credentialStoreNotInitialized();
        }
        if (credentialAlias == null || credentialAlias.trim().isEmpty()) {
            throw ROOT_LOGGER.credentialAliasRequired();
        }
        if (credential == null) {
            throw ROOT_LOGGER.credentialCannotBeNull();
        }

        VaultAlias alias = parseAlias(credentialAlias);

        try {
            final char[] chars = credential.castAndApply(PasswordCredential.class, c -> c.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword));
            if (chars == null) {
                throw ROOT_LOGGER.failedToExtractPasswordFromCredential();
            }
            vaultConnector.putSecretData(alias, new String(chars));
            putInCredentialCache(credentialAlias, credential);
        } catch (ClassCastException e) {
            throw ROOT_LOGGER.onlyPasswordCredentialWithClearPasswordSupported(e);
        }
    }

    @Override
    public <C extends Credential> C retrieve(String credentialAlias, Class<C> credentialType, String credentialAlgorithm, AlgorithmParameterSpec parameterSpec, CredentialStore.ProtectionParameter protectionParameter) throws CredentialStoreException {
        if (!initialized) {
            throw ROOT_LOGGER.credentialStoreNotInitialized();
        }
        if (credentialAlias == null || credentialAlias.trim().isEmpty()) {
            throw ROOT_LOGGER.credentialAliasRequired();
        }

        // Check cache first
        Credential cached;
        synchronized (credentialCache) {
            cached = credentialCache.get(credentialAlias);
        }
        if (credentialType.isInstance(cached)) {
            return credentialType.cast(cached);
        }

        VaultAlias alias = parseAlias(credentialAlias);

        try {
            // Retrieve full secret data from Vault
            Map<String, Object> secretData = vaultConnector.getSecretData(alias);
            if (secretData == null) {
                return null; // Secret not found
            }

            // Resolve the specific value using key path
            String value = KeyPathResolver.resolveKeyPath(secretData, alias.getKeyPath());
            if (value == null) {
                return null; // Key not found in secret
            }

            // Create credential from the value
            PasswordCredential credential = new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, value.toCharArray()));
            putInCredentialCache(credentialAlias, credential);
            return credentialType.cast(credential);
        } catch (ClassCastException e) {
            throw ROOT_LOGGER.unsupportedCredentialType(credentialType.getSimpleName(), e);
        }
    }

    @Override
    public void remove(String credentialAlias, Class<? extends Credential> credentialType, String credentialAlgorithm, AlgorithmParameterSpec parameterSpec) throws CredentialStoreException {
        if (!initialized) {
            throw ROOT_LOGGER.credentialStoreNotInitialized();
        }
        if (credentialAlias == null || credentialAlias.trim().isEmpty()) {
            throw ROOT_LOGGER.credentialAliasRequired();
        }

        VaultAlias alias = parseAlias(credentialAlias);

        vaultConnector.removeSecretData(alias);
        synchronized (credentialCache) {
            // Remove from cache - just this specific alias
            // Note: If the removal empties the secret, other keys at same path are also removed from Vault
            credentialCache.remove(credentialAlias);
        }
    }

    /**
     * Parse a credential alias string into a VaultAlias object.
     * Supports both new alias format and legacy format (if enabled).
     *
     * @param credentialAlias the alias string to parse
     * @return parsed VaultAlias object
     * @throws CredentialStoreException if parsing fails
     */
    private VaultAlias parseAlias(String credentialAlias) throws CredentialStoreException {
        return VaultAlias.parseWithLegacySupport(
            credentialAlias,
            this.defaultEngineType,
            this.defaultMountPath,
            this.supportLegacyAliasFormat
        );
    }

    private void putInCredentialCache(String alias, Credential credential) {
        synchronized (credentialCache) {
            credentialCache.put(alias, credential);
        }
    }

    private static char[] getStorePassword(final CredentialStore.ProtectionParameter protectionParameter) throws IOException, CredentialStoreException {
        final char[] password;
        if (protectionParameter instanceof CredentialStore.CredentialSourceProtectionParameter) {
            password = ((CredentialStore.CredentialSourceProtectionParameter) protectionParameter).
                    getCredentialSource()
                    .applyToCredential(PasswordCredential.class, c -> c.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword));
        } else if (protectionParameter != null) {
            throw log.invalidProtectionParameter(protectionParameter);
        } else {
            password = null;
        }
        return password;
    }

    @Override
    public Set<String> getAliases() throws UnsupportedOperationException, CredentialStoreException {
        // Use "secret/" as the default path when none provided
        return getAliases("secret/");
    }

    /**
     * Get aliases from a specific path in Vault.
     *
     * @param path the Vault path to start listing from (e.g., "secret"). If null or empty, throw exception
     * @return set of aliases in format "path.key", containing at most 10,000 aliases
     * @throws CredentialStoreException if listing aliases fails
     */
    public Set<String> getAliases(String path) throws CredentialStoreException {
        if (!initialized) {
            throw ROOT_LOGGER.credentialStoreNotInitialized();
        }
        if (path == null || path.trim().isEmpty()) {
            throw ROOT_LOGGER.emptyPathForGetAliases();
        }
        return collectAliases(normalizePath(path), false, 0);
    }

    /**
     * Get aliases from a specific path in Vault with optional recursive traversal.
     *
     * @param path the Vault path to start listing from. If null or empty, throw exception
     * @param recursive if true, traverse subpaths; if false, only list aliases at the specified path
     * @return set of aliases in format "path.key", containing at most 10,000 aliases
     * @throws CredentialStoreException if listing aliases fails
     */
    public Set<String> getAliases(String path, boolean recursive) throws CredentialStoreException {
        if (!initialized) {
            throw ROOT_LOGGER.credentialStoreNotInitialized();
        }
        if (path == null || path.trim().isEmpty()) {
            throw ROOT_LOGGER.emptyPathForGetAliases();
        }
        return collectAliases(normalizePath(path), recursive, DEFAULT_MAX_DEPTH);
    }

    /**
     * Get aliases from a specific path in Vault with optional recursive traversal.
     *
     * @param path the Vault path to start listing from. If null or empty, throw exception
     * @param recursive if true, traverse subpaths; if false, only list aliases at the specified path
     * @param recursiveDepth the maximum depth to traverse if recursive is true. 0 means only the specified path,
     *                       1 means one level deep, etc. Ignored if recursive is false.
     * @return set of aliases in format "path.key", containing at most 10,000 aliases
     * @throws CredentialStoreException if listing aliases fails
     */
    public Set<String> getAliases(String path, boolean recursive, int recursiveDepth) throws CredentialStoreException {
        if (!initialized) {
            throw ROOT_LOGGER.credentialStoreNotInitialized();
        }
        if (path == null || path.trim().isEmpty()) {
            throw ROOT_LOGGER.emptyPathForGetAliases();
        }
        if (recursiveDepth < 0) {
            throw ROOT_LOGGER.recursiveDepthMustBeNonNegative(recursiveDepth);
        }
        return collectAliases(normalizePath(path), recursive, recursiveDepth);
    }

    /**
     * Get aliases from a specific path in Vault with optional recursive traversal and maximum alias limit.
     *
     * @param path the Vault path to start listing from (e.g., "secret"). If null or empty, throw exception
     * @param recursive if true, traverse subpaths; if false, only list aliases at the specified path
     * @param recursiveDepth the maximum depth to traverse if recursive is true. 0 means only the specified path,
     *                       1 means one level deep, etc. Ignored if recursive is false.
     * @param maxNumberOfAliases the maximum number of aliases to return. Must be positive. Collection stops when this limit is reached.
     * @return set of aliases in format "path.key", containing at most maxNumberOfAliases aliases
     * @throws CredentialStoreException if listing aliases fails
     */
    public Set<String> getAliases(String path, boolean recursive, int recursiveDepth, int maxNumberOfAliases) throws CredentialStoreException {
        if (!initialized) {
            throw ROOT_LOGGER.credentialStoreNotInitialized();
        }
        if (path == null || path.trim().isEmpty()) {
            throw ROOT_LOGGER.emptyPathForGetAliases();
        }
        if (recursiveDepth < 0) {
            throw ROOT_LOGGER.recursiveDepthMustBeNonNegative(recursiveDepth);
        }
        if (maxNumberOfAliases <= 0) {
            throw ROOT_LOGGER.maxNumberOfAliasesMustBePositive(maxNumberOfAliases);
        }
        return collectAliases(normalizePath(path), recursive, recursiveDepth, maxNumberOfAliases);
    }

    private final HashicorpVaultCredentialStoreExtension credentialStoreExtension = new HashicorpVaultCredentialStoreExtension() {
        @Override
        public void setSslContext(SSLContext sslContext) {
            HashicorpVaultCredentialStore.this.setSslContext(sslContext);
        }

        @Override
        public void setKvV1FallbackPredicate(Predicate<String> kvV1FallbackPredicate) {
            HashicorpVaultCredentialStore.this.setKvV1FallbackPredicate(kvV1FallbackPredicate);
        }

        @Override
        public Set<String> getAliases(String path) throws CredentialStoreException {
            return HashicorpVaultCredentialStore.this.getAliases(path);
        }

        @Override
        public Set<String> getAliases(String path, boolean recursive) throws CredentialStoreException {
            return HashicorpVaultCredentialStore.this.getAliases(path, recursive);
        }

        @Override
        public Set<String> getAliases(String path, boolean recursive, int recursiveDepth) throws CredentialStoreException {
            return HashicorpVaultCredentialStore.this.getAliases(path, recursive, recursiveDepth);
        }

        @Override
        public Set<String> getAliases(String path, boolean recursive, int recursiveDepth, int maxNumberOfAliases) throws CredentialStoreException {
            return HashicorpVaultCredentialStore.this.getAliases(path, recursive, recursiveDepth, maxNumberOfAliases);
        }
    };

    @Override
    public <C extends CredentialStoreExtension> C getExtensionInstance(final Class<C> extensionType) {
        if (extensionType != null && extensionType.isInstance(credentialStoreExtension)) {
            return extensionType.cast(credentialStoreExtension);
        }
        return null;
    }

    @Override
    public List<Class<? extends CredentialStoreExtension>> getSupportedExtensionTypes() {
        return SUPPORTED_EXTENSION_TYPES;
    }


    private Set<String> collectAliases(String path, boolean recursive, int maxDepth) throws CredentialStoreException {
        return collectAliases(path, recursive, maxDepth, DEFAULT_MAX_ALIASES);
    }

    private Set<String> collectAliases(String path, boolean recursive, int maxDepth, int maxNumberOfAliases) throws CredentialStoreException {
        Set<String> aliases = new HashSet<>();
        collectAliasesRecursive(path, aliases, recursive, maxDepth, 0, maxNumberOfAliases);
        return aliases;
    }

    // TODO: Implement alias listing with new alias format
    // Keep an eye on https://github.com/hashicorp/vault/issues/5275 and remove this logic once hashicorp vault provides this operation
    // This method needs to be redesigned to work with the new alias format that supports:
    // - Custom mount paths (not just "secret")
    // - Nested JSON key paths (not just top-level keys)
    // - Different engine types (KVv1 vs KVv2)
    // The current implementation assumes legacy "path.key" format and needs VaultConnector methods that were removed.
    private void collectAliasesRecursive(String path, Set<String> aliases, boolean recursive, int maxDepth, int currentDepth, int maxNumberOfAliases) throws CredentialStoreException {
        throw new UnsupportedOperationException(
            "Alias listing is not yet implemented for the new alias format. " +
            "This feature requires redesign to support custom mount paths, nested JSON keys, and different engine types. " +
            "For now, you must know your alias names explicitly. " +
            "See https://github.com/wildfly-security/wildfly-elytron-hashicorp-vault/issues/70 for tracking."
        );

        // Original implementation (commented out - requires removed VaultConnector methods):
        /*
        if (aliases.size() >= maxNumberOfAliases) {
            return;
        }

        try {
            Set<String> keys = vaultConnector.getKeysForPath(path);
            for (String key : keys) {
                if (aliases.size() >= maxNumberOfAliases) {
                    return;
                }
                aliases.add(path + "." + key);
            }
        } catch (VaultException e) {
            if (e.getMessage() != null && e.getMessage().contains("Path does not exist")) {
                // ignore because this path in the tree can be empty, but other paths not so continue traversal
            } else {
                throw ROOT_LOGGER.couldNotReadKeysFromPath(path, currentDepth, recursive, e.getMessage(), e);
            }
        }

        if (recursive && currentDepth < maxDepth && aliases.size() < maxNumberOfAliases) {
            try {
                Set<String> items = vaultConnector.listAllItemsAtPath(path);
                if (items.isEmpty()) {
                    return;
                }
                for (String item : items) {
                    if (aliases.size() >= maxNumberOfAliases) {
                        return;
                    }
                    String fullItemPath = normalizePath(path) + "/" + item;
                    boolean isSubpath = item.endsWith("/");
                    if (!isSubpath) {
                        try {
                            Set<String> keys = vaultConnector.getKeysForPath(fullItemPath);
                            for (String key : keys) {
                                if (aliases.size() >= maxNumberOfAliases) {
                                    return;
                                }
                                aliases.add(fullItemPath + "." + key);
                            }
                        } catch (VaultException e) {
                            // Path doesn't have keys or doesn't exist - continue with other paths
                        }
                    } else {
                        collectAliasesRecursive(fullItemPath, aliases, recursive, maxDepth, currentDepth + 1, maxNumberOfAliases);
                    }
                }
            } catch (VaultException e) {
                String errorMsg = e.getMessage();
                if (errorMsg != null && errorMsg.contains("403")) {
                    throw ROOT_LOGGER.forbiddenToListSubpathsAtCredentialStorePath(path, e);
                }
            }
        }
        */
    }

    private String normalizePath(String path) {
        return path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
    }
}
