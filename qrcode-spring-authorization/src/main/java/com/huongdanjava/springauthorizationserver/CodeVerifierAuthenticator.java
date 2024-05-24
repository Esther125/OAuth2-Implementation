package com.huongdanjava.springauthorizationserver;


import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

final class CodeVerifierAuthenticator {
    private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType("code");
    private final Log logger = LogFactory.getLog(this.getClass());
    private final OAuth2AuthorizationService authorizationService;

    CodeVerifierAuthenticator(OAuth2AuthorizationService authorizationService) {
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        this.authorizationService = authorizationService;
    }

    void authenticateRequired(OAuth2ClientAuthenticationToken clientAuthentication, RegisteredClient registeredClient) {
        if (!this.authenticate(clientAuthentication, registeredClient)) {
            throwInvalidGrant("code_verifier");
        }
    }

    void authenticateIfAvailable(OAuth2ClientAuthenticationToken clientAuthentication, RegisteredClient registeredClient) {
        this.authenticate(clientAuthentication, registeredClient);
    }

    private boolean authenticate(OAuth2ClientAuthenticationToken clientAuthentication, RegisteredClient registeredClient) {
        Map<String, Object> parameters = clientAuthentication.getAdditionalParameters();
        if (!authorizationCodeGrant(parameters)) {
            return false;
        } else {
            OAuth2Authorization authorization = this.authorizationService.findByToken((String)parameters.get("code"), AUTHORIZATION_CODE_TOKEN_TYPE);
            if (authorization == null) {
                throwInvalidGrant("code");
            }

            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Retrieved authorization with authorization code");
            }

            OAuth2AuthorizationRequest authorizationRequest = (OAuth2AuthorizationRequest)authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());

            String codeChallenge = (String)authorizationRequest.getAdditionalParameters().get("code_challenge");
            if (!StringUtils.hasText(codeChallenge)) {
                if (!registeredClient.getClientSettings().isRequireProofKey()) {
                    if (this.logger.isTraceEnabled()) {
                        this.logger.trace("Did not authenticate code verifier since requireProofKey=false");
                    }

                    return false;
                }

                throwInvalidGrant("code_challenge");
            }

            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Validated code verifier parameters");
            }

            String codeChallengeMethod = (String)authorizationRequest.getAdditionalParameters().get("code_challenge_method");
            String codeVerifier = (String)parameters.get("code_verifier");
            if (!codeVerifierValid(codeVerifier, codeChallenge, codeChallengeMethod)) {
                throwInvalidGrant("code_verifier");
            }

            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Authenticated code verifier");
            }

            return true;
        }
    }

    private static boolean authorizationCodeGrant(Map<String, Object> parameters) {
        return AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(parameters.get("grant_type")) && parameters.get("code") != null;
    }

    private static boolean codeVerifierValid(String codeVerifier, String codeChallenge, String codeChallengeMethod) {
        if (!StringUtils.hasText(codeVerifier)) {
            return false;
        } else if ("S256".equals(codeChallengeMethod)) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] digest = md.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
                String encodedVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
                return encodedVerifier.equals(codeChallenge);
            } catch (NoSuchAlgorithmException var6) {
                throw new OAuth2AuthenticationException("server_error");
            }
        } else {
            return false;
        }
    }

    private static void throwInvalidGrant(String parameterName) {
        OAuth2Error error = new OAuth2Error("invalid_grant", "Client authentication failed: " + parameterName, (String)null);
        throw new OAuth2AuthenticationException(error);
    }
}
