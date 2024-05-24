package com.huongdanjava.springauthorizationserver.controller;

import com.huongdanjava.springauthorizationserver.JwtUserInfoMapperSecurityConfig;
import com.huongdanjava.springauthorizationserver.OidcUserInfoService;
import com.huongdanjava.springauthorizationserver.data.*;
import com.huongdanjava.springauthorizationserver.service.JWTService;
import com.huongdanjava.springauthorizationserver.service.RedisService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.context.request.async.DeferredResult;
import org.springframework.web.util.UriComponentsBuilder;

import javax.security.auth.Subject;

import java.security.Principal;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;

@Controller
public class LoginController {
    @Autowired
    private RedisService redisService;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private RegisteredClientRepository registeredClientRepository;
    @Autowired
    private OAuth2AuthorizationService authorizationService;
    @Autowired
    private JwtUserInfoMapperSecurityConfig jwtUserInfoMapperSecurityConfig;

    private static final Logger logger = LoggerFactory.getLogger(LoginController.class);
    private final ExecutorService rtExecutor = Executors.newFixedThreadPool(10);

    private String getIpAddressHash(HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        String extIpAddress = request.getHeader("X-FORWARDED-FOR");
        if (extIpAddress != null) {
            ipAddress = extIpAddress + "-" + ipAddress;
        }
        return ipAddress;
    }

    @GetMapping("/login")
    public String customLoginPage() {
        return "login";
    }

    @PostMapping(path = "/login/plt", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public ResponseEntity<?> produceLoginToken(
            HttpServletRequest request,
            @RequestBody ClientDetails clientDetails) {
        try {
            String ip = getIpAddressHash(request) + "-"+ UUID.randomUUID().toString().replace("-", "");
            String redisKey = LoginToken.getRedisKey(ip);
            LoginToken existedLoginToken = LoginToken.fromJsonStr((String)redisService.getAndDelete(redisKey));
            if (existedLoginToken != null)
                return ResponseEntity.ok(existedLoginToken);

            long now = System.currentTimeMillis();
            LoginToken loginToken = LoginToken.builder()
                .ip(ip)
                .t(now)
                .ttl(now + 300*1000) // 300s
                .token(UUID.randomUUID().toString().replace("-", ""))
                .client_id(clientDetails.getClient_id())
                .state(clientDetails.getState())
                .build();
            redisService.set(redisKey, loginToken.toJsonStr(), 300);
            return ResponseEntity.ok(loginToken);

        } catch (Exception e) {
            System.out.println("錯誤:"+e.toString());
        }
        return ResponseEntity.internalServerError().build();
    }

    @PostMapping(path = "/login/wait", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public DeferredResult<LoginConsumeToken> waitConsumingLoginToken(
            HttpServletRequest request,
            @RequestBody WaitLoginConsumeBody waitLoginConsumeBody
    ) {
        String ip = waitLoginConsumeBody.getIp();
        String loginTokenRedisKey = LoginToken.getRedisKey(ip);
        Map<String,String> options = waitLoginConsumeBody.getOptions();

        DeferredResult<LoginConsumeToken> output = new DeferredResult<>(300000L);
        rtExecutor.execute(() -> {
            try {
                LoginToken loginToken = LoginToken.fromJsonStr((String)redisService.getAndDelete(loginTokenRedisKey));
                if (loginToken == null) {
                    output.setErrorResult(ResponseEntity.badRequest().build());
                    return;
                }

                String token = waitLoginConsumeBody.getToken();
                String loginConsumeTokenRedisKey = LoginConsumeToken.getRedisKey(token);
                System.out.println("wait key: "+loginConsumeTokenRedisKey);
                int count = 0;
                while(count < 150) {
                    Thread.sleep(2000);
                    LoginConsumeToken loginConsumeToken = LoginConsumeToken.fromJsonStr((String)redisService.getAndDelete(loginConsumeTokenRedisKey));
                    if (loginConsumeToken != null) {
                        String result = loginConsumeToken.getResult();
                        loginConsumeToken.setResult(result);
                        output.setResult(loginConsumeToken);
                        System.out.println("登入成功");
                        return;
                    }
                    System.out.println("計次"+count);
                    count++;
                }
                logger.info("登入失敗");
                output.setErrorResult(ResponseEntity.notFound().build());
            } catch (Exception e) {
                output.setErrorResult(ResponseEntity.internalServerError());
            }
        });
        return output;
    }

    @PostMapping(path = "/login/clt", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> consumeLoginToken(
            // include userName, password, token, client_id and state
            @RequestBody TokenBody tokenBody
    ) {
        try {
            // check userName and password
            String userName = tokenBody.getUserName();
            String password = tokenBody.getPassword();

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(userName, password));

            // get info from registeredClient using client_id
            RegisteredClient registeredClient = registeredClientRepository.findByClientId(tokenBody.getClient_id());

            Set<String> redirectUris = registeredClient.getRedirectUris();
            String redirectUriString = String.join(" ", redirectUris);
            Set<String> scopes = registeredClient.getScopes();

            // build authorizationRequest
            OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("http://172.26.93.64:8080")
                .clientId(registeredClient.getClientId())
                .redirectUri(redirectUriString)
                .scopes(scopes)
                .build();

            // use code (from /login/plt) as RedisKey
            String loginToken = tokenBody.getToken();
            String loginConsumeTokenRedisKey = LoginConsumeToken.getRedisKey(loginToken);

            // generate authorization code and refresh token
            OAuth2TokenContext context = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(authentication)
                .authorizationGrantType(AUTHORIZATION_CODE)
                .authorizationGrant(authentication)
                .authorizedScopes(scopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build();

            OAuth2TokenContext context2 = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(authentication)
                .authorizationGrantType(AUTHORIZATION_CODE)
                .authorizationGrant(authentication)
                .authorizedScopes(scopes)
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .build();

            OAuth2TokenGenerator<OAuth2Token> generator = jwtUserInfoMapperSecurityConfig.authorizationCodeGenerator();
            OAuth2Token code = Objects.requireNonNull(generator.generate(context));
            String codeStr = code.getTokenValue();

            OAuth2Token refreshToken = Objects.requireNonNull(generator.generate(context2));
            String refreshTokenStr = refreshToken.getTokenValue();

            Instant issuedAt = Instant.now();
            OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(userName)
                .authorizationGrantType(AUTHORIZATION_CODE)
                .attribute(OAuth2ParameterNames.REDIRECT_URI, redirectUriString)
                .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest)
                .attribute(Principal.class.getName(), authentication)
                .token(code)
                .authorizedScopes(scopes)
                .refreshToken(new OAuth2RefreshToken(refreshTokenStr,issuedAt))
                .build();
            authorizationService.save(authorization);

            // build redirect_uri for frontend
            String result = UriComponentsBuilder.fromUriString(redirectUriString)
                .queryParam("code", codeStr)
                .queryParam("state",tokenBody.getState())
                .toUriString();
            
            LoginConsumeToken loginConsumeToken = LoginConsumeToken.builder()
                .result(result)
                .build();
            redisService.set(loginConsumeTokenRedisKey, loginConsumeToken.toJsonStr());

            logger.info("clt key: " + loginConsumeTokenRedisKey);
            return ResponseEntity.status(HttpStatus.OK).body("驗證成功");
        }
        catch (AuthenticationException e) {
            logger.info("Authentication failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        catch (Exception e) {
            logger.error("An unexpected error occurred: " + e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}
