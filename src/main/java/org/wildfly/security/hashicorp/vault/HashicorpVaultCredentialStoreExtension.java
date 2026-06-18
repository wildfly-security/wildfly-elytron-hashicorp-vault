/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import java.util.Set;

import javax.net.ssl.SSLContext;

import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.CredentialStoreExtension;

/**
 * Extension API for Hashicorp Vault credential store. Exposes only store-specific operations
 * that do not belong to {@link org.wildfly.security.credential.store.CredentialStoreSpi}.
 */
public interface HashicorpVaultCredentialStoreExtension extends CredentialStoreExtension {

    void setSslContext(SSLContext sslContext);

    /**
     * Get aliases from a specific path in Vault.
     *
     * @param path the Vault path to start listing from. If null or empty, throws exception
     * @return set of aliases in format "path.key", containing at most 10,000 aliases
     * @throws CredentialStoreException if listing aliases fails
     */
    Set<String> getAliases(String path) throws CredentialStoreException;

    /**
     * Get aliases from a specific path in Vault with optional recursive traversal.
     *
     * @param path the Vault path to start listing from. If null or empty, throws exception
     * @param recursive if true, traverse subpaths; if false, only list aliases at the specified path
     * @return set of aliases in format "path.key", containing at most 10,000 aliases
     * @throws CredentialStoreException if listing aliases fails
     */
    Set<String> getAliases(String path, boolean recursive) throws CredentialStoreException;

    /**
     * Get aliases from a specific path in Vault with optional recursive traversal.
     *
     * @param path the Vault path to start listing from. If null or empty, throws exception
     * @param recursive if true, traverse subpaths; if false, only list aliases at the specified path
     * @param recursiveDepth the maximum depth to traverse if recursive is true. 0 means only the specified path,
     *                       1 means one level deep, etc. Ignored if recursive is false.
     * @return set of aliases in format "path.key", containing at most 10,000 aliases
     * @throws CredentialStoreException if listing aliases fails
     */
    Set<String> getAliases(String path, boolean recursive, int recursiveDepth) throws CredentialStoreException;

    /**
     * Get aliases from a specific path in Vault with optional recursive traversal and maximum alias limit.
     *
     * @param path the Vault path to start listing from. If null or empty, throws exception
     * @param recursive if true, traverse subpaths; if false, only list aliases at the specified path
     * @param recursiveDepth the maximum depth to traverse if recursive is true. 0 means only the specified path,
     *                       1 means one level deep, etc. Ignored if recursive is false.
     * @param maxNumberOfAliases the maximum number of aliases to return.
     * @return set of aliases in format "path.key", containing at most maxNumberOfAliases aliases
     * @throws CredentialStoreException if listing aliases fails
     */
    Set<String> getAliases(String path, boolean recursive, int recursiveDepth, int maxNumberOfAliases) throws CredentialStoreException;
}
