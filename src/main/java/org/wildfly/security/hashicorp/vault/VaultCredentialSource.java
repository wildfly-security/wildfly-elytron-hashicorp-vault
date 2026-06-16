/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import static org.wildfly.security.hashicorp.vault._private.HashiCorpVaultLogger.ROOT_LOGGER;

import java.io.IOException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.function.Supplier;

import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 *  A credential source which is backed by a HashiCorp Vault.
 */
class VaultCredentialSource implements CredentialSource {

    private final VaultConnector vaultConnector;
    private final String secretPath;
    private final String secretKey;

    public static Supplier<Provider[]> ELYTRON_PASSWORD_PROVIDERS = () -> new Provider[]{
            WildFlyElytronPasswordProvider.getInstance()
    };

    /**
     * Construct a new instance.
     *
     * @param vaultConnector the service connecting to vault instance (must not be {@code null})
     * @param secretPath the path to the secret to retrieve from (must not be {@code null})
     * @param secretKey the key of the secret
     */
    public VaultCredentialSource(VaultConnector vaultConnector, String secretPath, String secretKey) {
        if (vaultConnector == null) {
            throw ROOT_LOGGER.vaultConnectorCannotBeNull();
        }
        if (secretPath == null || secretPath.trim().isEmpty()) {
            throw ROOT_LOGGER.vaultSecretPathInvalid();
        }
        if (secretKey == null || secretKey.trim().isEmpty()) {
            throw ROOT_LOGGER.vaultSecretKeyInvalid();
        }

        this.vaultConnector = vaultConnector;
        this.secretPath = secretPath;
        this.secretKey = secretKey;
    }

    //TODO support more credential types
    public boolean isCredentialSupported(Class<? extends Credential> credentialType, String algorithm,
                                         AlgorithmParameterSpec parameterSpec) throws IOException {
        return credentialType == PasswordCredential.class &&
                (algorithm == null || ClearPassword.ALGORITHM_CLEAR.equals(algorithm));
    }

    @Override
    public <C extends Credential> C getCredential(Class<C> credentialType, String algorithm,
                                                  AlgorithmParameterSpec parameterSpec) throws IOException {
        //TODO support more credential types
        if (credentialType == PasswordCredential.class) {
            try {
                vaultConnector.configure();
                String password = vaultConnector.getSecret(secretPath, secretKey);
                if (password != null) {
                    PasswordFactory factory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR, ELYTRON_PASSWORD_PROVIDERS);
                    ClearPassword clearPassword = (ClearPassword) factory.generatePassword(
                            new ClearPasswordSpec(password.toCharArray()));
                    return credentialType.cast(new PasswordCredential(clearPassword));
                }
            } catch (Exception e) {
                throw ROOT_LOGGER.failedToRetrieveCredentialFromVaultIo(e.getMessage(), e);
            }
        }

        return null;
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName,
                                                    AlgorithmParameterSpec parameterSpec) throws IOException {
        if (isCredentialSupported(credentialType, algorithmName, parameterSpec)) {
            return SupportLevel.SUPPORTED;
        }
        return SupportLevel.UNSUPPORTED;
    }
}