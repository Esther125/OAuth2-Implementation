package com.huongdanjava.springauthorizationserver;

import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;

import java.time.Instant;


public class OAuth2AuthorizationCode extends AbstractOAuth2Token {

    public OAuth2AuthorizationCode(String tokenValue, Instant issuedAt, Instant expiresAt) {
        super(tokenValue, issuedAt, expiresAt);
    }

    @Override
    public String getTokenValue() {
        return super.getTokenValue();
    }

}