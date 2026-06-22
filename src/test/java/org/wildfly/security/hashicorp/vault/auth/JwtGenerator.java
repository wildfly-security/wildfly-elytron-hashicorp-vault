/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.hashicorp.vault.auth;

import java.security.PrivateKey;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

/**
 * Utility to generate JWTs based on jose4j
 */
public class JwtGenerator {

    private final String issuer;
    private final String audience;
    private final String subject;

    private JwtGenerator(Builder builder) {
        this.issuer = builder.issuer;
        this.audience = builder.audience;
        this.subject = builder.subject;
    }

    public String generateJwt(PrivateKey privateKey) throws JoseException {
        // Create standard claims
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(this.issuer);
        claims.setAudience(this.audience);
        claims.setSubject(this.subject);
        claims.setExpirationTimeMinutesInTheFuture(60);
        claims.setIssuedAtToNow();
        claims.setClaim("scope", "vault.read");

        // Create signer
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKey(privateKey);
        jws.setHeader("typ", "JWT");

        return jws.getCompactSerialization();
    }

    public static final class Builder {

        private String issuer;
        private String audience;
        private String subject;

        /**
         * must match Vault bound_issuer
         * @param issuer issuer name
         * @return instance of this builder
         */
        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        /**
         * must match bound_audiences
         * @param audience audiences name
         * @return instance of this builder
         */
        public Builder audience(String audience) {
            this.audience = audience;
            return this;
        }

        /**
         * must be same value as claim configured in user_claim
         * @param subject subject name
         * @return instance of this builder
         */
        public Builder subject(String subject) {
            this.subject = subject;
            return this;
        }

        public JwtGenerator build() {
            return new JwtGenerator(this);
        }
    }


}
