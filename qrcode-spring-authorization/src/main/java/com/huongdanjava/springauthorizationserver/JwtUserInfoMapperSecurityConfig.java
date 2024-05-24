package com.huongdanjava.springauthorizationserver;

import com.huongdanjava.springauthorizationserver.controller.LoginController;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class JwtUserInfoMapperSecurityConfig {
    @Autowired
    private AuthorizationServerConfiguration authorizationServerConfiguration;
    @Autowired
    private OidcUserInfoService oidcUserInfoService;

    private static final Logger logger = LoggerFactory.getLogger(LoginController.class);

    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        // userInfo endpoint settings
        Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper = (context) -> {
            OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
            String username = authentication.getName();

            return oidcUserInfoService.loadUser(username);
        };

        authorizationServerConfigurer.oidc((oidc) ->
                oidc.userInfoEndpoint((userInfo) -> userInfo.userInfoMapper(userInfoMapper)));

        http
            .securityMatcher(endpointsMatcher)
            .authorizeHttpRequests((authorize) -> authorize.anyRequest().permitAll())
            .httpBasic(withDefaults())
            .csrf(csrf -> csrf.disable())
            .oauth2ResourceServer(resourceServer -> resourceServer.jwt(withDefaults()))
            .exceptionHandling((exceptions) -> exceptions
                .defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
            .apply(authorizationServerConfigurer);

        return http.build();
    }

    @Bean
    public OAuth2TokenGenerator<OAuth2Token> authorizationCodeGenerator() {
        return context -> {
            if(context.getTokenType().getValue().equals(OAuth2TokenType.REFRESH_TOKEN.getValue())){
                OAuth2RefreshToken oAuth2RefreshToken = new OAuth2RefreshTokenGenerator().generate(context);
                return oAuth2RefreshToken;
            }else if(context.getTokenType().getValue().equals(OAuth2TokenType.ACCESS_TOKEN.getValue())) {

                Map<String, Object> claims = new HashMap<>();
                claims.put("sub", context.getPrincipal().getName()); // admin
                claims.put("aud", context.getRegisteredClient().getClientId()); //wekan
                claims.put("scope", context.getRegisteredClient().getScopes());

                Map<String, Object> headers = new LinkedHashMap<>();
                headers.put("alg", "RS256");
                headers.put("typ", "JWT");

                Instant issuedAt = Instant.now();
                Instant expiresAt = issuedAt.plusSeconds(3600);

                PrivateKey privateKey;
                try {
                    RSAKey rsaKey = authorizationServerConfiguration.generateRsa();
                    privateKey = rsaKey.toPrivateKey();
                    headers.put("kid",rsaKey.getKeyID());
                } catch (JOSEException | NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
                String jwtString = Jwts.builder()
                    .setClaims(claims)
                    .setIssuedAt(Date.from(issuedAt))
                    .setExpiration(Date.from(expiresAt))
                    .signWith(privateKey, SignatureAlgorithm.RS256)
                    .compact();

                return new OAuth2AuthorizationCode(jwtString, issuedAt, expiresAt);

            }else if(context.getTokenType().getValue().equals(new OAuth2TokenType("id_token").getValue())){
                Map<String, Object> claims = new HashMap<>();
                claims.put("sub", context.getPrincipal().getName()); // admin
                claims.put("aud", context.getRegisteredClient().getClientId()); //wekan
                claims.put("scope",context.getRegisteredClient().getScopes());
                claims.put("iss","http://localhost:8080");

                Map<String, Object> headers = new LinkedHashMap<>();
                headers.put("alg", "RS256");
                headers.put("typ", "JWT");

                Instant issuedAt = Instant.now();
                Instant expiresAt = issuedAt.plusSeconds(3600);

                PrivateKey privateKey;
                try {
                    RSAKey rsaKey = authorizationServerConfiguration.generateRsa();
                    privateKey = rsaKey.toPrivateKey();
                    headers.put("kid",rsaKey.getKeyID());
                } catch (JOSEException | NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }

                String jwtString = Jwts.builder()
                    .setClaims(claims)
                    .setIssuedAt(Date.from(issuedAt))
                    .setExpiration(Date.from(expiresAt))
                    .signWith(privateKey, SignatureAlgorithm.RS256)
                    .compact();

                return new Jwt(jwtString, issuedAt, expiresAt,headers, claims);
            }
            else{
                return null;
            }

        };
    }
};
