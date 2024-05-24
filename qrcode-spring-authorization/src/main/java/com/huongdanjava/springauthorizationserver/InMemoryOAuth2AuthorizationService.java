package com.huongdanjava.springauthorizationserver;


import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public final class InMemoryOAuth2AuthorizationService implements OAuth2AuthorizationService {
    private int maxInitializedAuthorizations;
    private Map<String, OAuth2Authorization> initializedAuthorizations;
    private final Map<String, OAuth2Authorization> authorizations;

    InMemoryOAuth2AuthorizationService(int maxInitializedAuthorizations) {
        this.maxInitializedAuthorizations = 100;
        this.initializedAuthorizations = Collections.synchronizedMap(new InMemoryOAuth2AuthorizationService.MaxSizeHashMap(this.maxInitializedAuthorizations));
        this.authorizations = new ConcurrentHashMap();
        this.maxInitializedAuthorizations = maxInitializedAuthorizations;
        this.initializedAuthorizations = Collections.synchronizedMap(new InMemoryOAuth2AuthorizationService.MaxSizeHashMap(this.maxInitializedAuthorizations));
    }

    public InMemoryOAuth2AuthorizationService() {
        this(Collections.emptyList());
    }

    public InMemoryOAuth2AuthorizationService(OAuth2Authorization... authorizations) {
        this(Arrays.asList(authorizations));
    }

    public InMemoryOAuth2AuthorizationService(List<OAuth2Authorization> authorizations) {
        this.maxInitializedAuthorizations = 100;
        this.initializedAuthorizations = Collections.synchronizedMap(new MaxSizeHashMap(this.maxInitializedAuthorizations));
        this.authorizations = new ConcurrentHashMap();
        Assert.notNull(authorizations, "authorizations cannot be null");
        authorizations.forEach((authorization) -> {
            Assert.notNull(authorization, "authorization cannot be null");
            Assert.isTrue(!this.authorizations.containsKey(authorization.getId()), "The authorization must be unique. Found duplicate identifier: " + authorization.getId());
            this.authorizations.put(authorization.getId(), authorization);
        });
    }

    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        if (isComplete(authorization)) {
            this.authorizations.put(authorization.getId(), authorization);
        } else {
            this.initializedAuthorizations.put(authorization.getId(), authorization);
        }

    }

    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        if (isComplete(authorization)) {
            this.authorizations.remove(authorization.getId(), authorization);
        } else {
            this.initializedAuthorizations.remove(authorization.getId(), authorization);
        }
    }

    @Nullable
    public OAuth2Authorization findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        OAuth2Authorization authorization = (OAuth2Authorization)this.authorizations.get(id);
        return authorization != null ? authorization : (OAuth2Authorization)this.initializedAuthorizations.get(id);
    }

//    @Nullable
//    public OAuth2Authorization findByToken(String token, @Nullable OAuth2TokenType tokenType) {
//        Assert.hasText(token, "token cannot be empty");
//        Iterator var3 = this.authorizations.values().iterator();
//
//        OAuth2Authorization authorization;
//        do {
//            if (!var3.hasNext()) {
//                var3 = this.initializedAuthorizations.values().iterator();
//
//                do {
//                    if (!var3.hasNext()) {
//                        return null;
//                    }
//
//                    authorization = (OAuth2Authorization)var3.next();
//                } while(!hasToken(authorization, token, tokenType));
//
//                return authorization;
//            }
//
//            authorization = (OAuth2Authorization)var3.next();
//        } while(!hasToken(authorization, token, tokenType));
//
//        return authorization;
//    }
    @Nullable
    public OAuth2Authorization findByToken(String token, @Nullable OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");

        // combine two sets
        List<OAuth2Authorization> allAuthorizations = new ArrayList<>();
        allAuthorizations.addAll(this.authorizations.values());
        allAuthorizations.addAll(this.initializedAuthorizations.values());

        // iterate
        for (OAuth2Authorization authorization : allAuthorizations) {
            if (hasToken(authorization, token, tokenType)) {
                return authorization;
            }
        }
        return null;
    }

    private static boolean isComplete(OAuth2Authorization authorization) {
        return authorization.getAccessToken() != null;
    }

    private static boolean hasToken(OAuth2Authorization authorization, String token, @Nullable OAuth2TokenType tokenType) {
        if (tokenType != null) {
            if ("state".equals(tokenType.getValue())) {
                return matchesState(authorization, token);
            } else if ("code".equals(tokenType.getValue())) {
                return matchesAuthorizationCode(authorization, token);
            } else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
                return matchesAccessToken(authorization, token);
            } else if ("id_token".equals(tokenType.getValue())) {
                return matchesIdToken(authorization, token);
            } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
                return matchesRefreshToken(authorization, token);
            } else if ("device_code".equals(tokenType.getValue())) {
                return matchesDeviceCode(authorization, token);
            } else {
                return "user_code".equals(tokenType.getValue()) ? matchesUserCode(authorization, token) : false;
            }
        } else {
            return matchesState(authorization, token) || matchesAuthorizationCode(authorization, token) || matchesAccessToken(authorization, token) || matchesIdToken(authorization, token) || matchesRefreshToken(authorization, token) || matchesDeviceCode(authorization, token) || matchesUserCode(authorization, token);
        }
    }

    private static boolean matchesState(OAuth2Authorization authorization, String token) {
        return token.equals(authorization.getAttribute("state"));
    }

    private static boolean matchesAuthorizationCode(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode> authorizationCode = authorization.getToken(org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode.class);
        return authorizationCode != null && ((OAuth2AuthorizationCode)authorizationCode.getToken()).getTokenValue().equals(token);
    }

    private static boolean matchesAccessToken(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getToken(OAuth2AccessToken.class);
        return accessToken != null && ((OAuth2AccessToken)accessToken.getToken()).getTokenValue().equals(token);
    }

    private static boolean matchesRefreshToken(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getToken(OAuth2RefreshToken.class);
        return refreshToken != null && ((OAuth2RefreshToken)refreshToken.getToken()).getTokenValue().equals(token);
    }

    private static boolean matchesIdToken(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OidcIdToken> idToken = authorization.getToken(OidcIdToken.class);
        return idToken != null && ((OidcIdToken)idToken.getToken()).getTokenValue().equals(token);
    }

    private static boolean matchesDeviceCode(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2DeviceCode> deviceCode = authorization.getToken(OAuth2DeviceCode.class);
        return deviceCode != null && ((OAuth2DeviceCode)deviceCode.getToken()).getTokenValue().equals(token);
    }

    private static boolean matchesUserCode(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2UserCode> userCode = authorization.getToken(OAuth2UserCode.class);
        return userCode != null && ((OAuth2UserCode)userCode.getToken()).getTokenValue().equals(token);
    }

    private static final class MaxSizeHashMap<K, V> extends LinkedHashMap<K, V> {
        private final int maxSize;
        private MaxSizeHashMap(int maxSize) {
            this.maxSize = maxSize;
        }

        protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
            return this.size() > this.maxSize;
        }
    }
}
