/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault;

/**
 * Shared string constants used across the HashiCorp Vault credential store implementation.
 */
final class VaultConstants {

    static final String ENGINE_TYPE_KV_V1 = "KVv1";
    static final String ENGINE_TYPE_KV_V2 = "KVv2";
    static final String DEFAULT_MOUNT_PATH = "secret";

    private VaultConstants() {
    }
}
