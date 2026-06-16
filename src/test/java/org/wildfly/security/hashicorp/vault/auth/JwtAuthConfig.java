/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault.auth;

import java.util.AbstractMap;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Stream;

import org.testcontainers.vault.VaultContainer;

/**
 * Configure JWT authentication - enable the auth itself and configure a role
 */
public class JwtAuthConfig  implements VaultContainerAuthConfig {

    private final String roleName;
    private final String boundAudiences;
    private final String userClaim;

    private final List<String> policies;
    private final List<String> jwtValidationPubkeys;

    private JwtAuthConfig(Builder builder) {
        this.roleName = builder.roleName;
        this.boundAudiences = builder.boundAudiences;
        this.userClaim = builder.userClaim;

        this.policies = builder.policies;
        this.jwtValidationPubkeys = builder.jwtValidationPubkeys;
    }

    @Override
    public void configure(VaultContainer<?> vaultContainer) {
        vaultContainer.withInitCommand("auth enable jwt");
        vaultContainer.withInitCommand("write auth/jwt/config \\\n" +
                //https://developer.hashicorp.com/vault/api-docs/auth/jwt#jwt_validation_pubkeys
                "   jwt_validation_pubkeys=\"" + String.join(",", this.jwtValidationPubkeys) + "\"");
        vaultContainer.withInitCommand("write auth/jwt/role/" + this.roleName + " \\\n" +
                //necessary for pure JWT (non-OIDC) authentication
                "    role_type=jwt \\\n" +
                "    bound_audiences=\"" + this.boundAudiences + "\" \\\n" +
                "    user_claim=\"" + this.userClaim + "\" \\\n" +
                "    policies=" + String.join(",", policies) + " \\\n" +
                "    ttl=1h");
    }

    public static final class Builder {

        private final String roleName;

        private String boundAudiences;
        private String userClaim;

        private final List<String> jwtValidationPubkeys = new LinkedList<>();
        private final List<String> policies = new LinkedList<>();

        /**
         * Create a new instance with a specific role name
         * @param roleName name of newly created role under auth/jwt/role
         */
        public Builder(String roleName) {
            this.roleName = roleName;
        }

        /**
         * A list of PEM-encoded public keys to use to authenticate signatures locally. Cannot be used with "jwks_url"
         * or "oidc_discovery_url".
         * @see <a href="https://developer.hashicorp.com/vault/api-docs/auth/jwt#jwt_validation_pubkeys">...</a>
         * @param jwtValidationPubkeys PEM-encoded public keys
         * @return instance of this builder
         */
        public Builder jwtValidationPubkeys(String... jwtValidationPubkeys) {
            this.jwtValidationPubkeys.addAll(List.of(jwtValidationPubkeys));
            return this;
        }

        public Builder boundAudiences(String boundAudiences) {
            this.boundAudiences = boundAudiences;
            return this;
        }

        /**
         * Set a name of the claim which will be used for the subject to identify the user from the token (the common
         * name is "sub")
         * @param userClaim name of the claim
         * @return instance of this builder
         */
        public Builder userClaim(String userClaim) {
            this.userClaim = userClaim;
            return  this;
        }

        /**
         * List of policies the user will have assigned within the newly configured role
         * @param policies names of policies
         * @return instance of this builder
         */
        public Builder policies(String... policies) {
            this.policies.addAll(List.of(policies));
            return this;
        }

        public void validate() {
            Stream.of(
                    new AbstractMap.SimpleEntry<>(roleName, "Missing role name"),
                    new AbstractMap.SimpleEntry<>(boundAudiences, "Missing bound audiences"),
                    new AbstractMap.SimpleEntry<>(userClaim, "Missing user claim")
            ).forEach(e -> {
                if (e.getKey() == null) throw new IllegalStateException(e.getValue());
            });

            if (policies.isEmpty()) {
                throw new IllegalStateException("Missing policies");
            }
        }

        public JwtAuthConfig build() {
            validate();
            return new JwtAuthConfig(this);
        }

    }
}
