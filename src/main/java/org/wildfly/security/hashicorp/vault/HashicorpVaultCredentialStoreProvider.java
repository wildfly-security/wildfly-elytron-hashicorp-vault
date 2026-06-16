/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

import java.security.Provider;
import java.util.Collections;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.WildFlyElytronBaseProvider;

@MetaInfServices(Provider.class)
public class HashicorpVaultCredentialStoreProvider extends WildFlyElytronBaseProvider {

    private static final long serialVersionUID = -6290509111783186244L;
    private static HashicorpVaultCredentialStoreProvider INSTANCE = new HashicorpVaultCredentialStoreProvider();

    /**
     * Construct a new instance.
     */
    public HashicorpVaultCredentialStoreProvider() {
        super("WildFlyElytronHashicorpVaultProvider", "1.0", "WildFly Elytron HashiCorp Vault CredentialStore Provider");
        putService(new Service(this, "CredentialStore", "HashicorpVaultCredentialStore",
                "org.wildfly.security.hashicorp.vault.HashicorpVaultCredentialStore",
                Collections.emptyList(), Collections.emptyMap()));
    }

    /**
     * Get the credential store implementations provider instance.
     *
     * @return the credential store implementations provider instance
     */
    public static HashicorpVaultCredentialStoreProvider getInstance() {
        return INSTANCE;
    }

}
