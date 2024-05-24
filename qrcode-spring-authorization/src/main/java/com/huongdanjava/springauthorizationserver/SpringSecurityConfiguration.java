package com.huongdanjava.springauthorizationserver;

import com.huongdanjava.springauthorizationserver.OidcUserInfoService.UserInfoRepository;
import com.huongdanjava.springauthorizationserver.filters.RateLimitFilter;
import jakarta.servlet.DispatcherType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfiguration {

  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(authorizeRequests -> authorizeRequests
            .requestMatchers("/*/login/plt","/*/s2s/**").permitAll()
            .anyRequest().permitAll())
        .formLogin(form -> form
            .loginPage("/login")
            .permitAll())
        .csrf(csrf -> csrf.disable());

    return http.build();
  }

  @Bean
  public UserDetailsService users() {
    // @formatter:off
    UserDetails user = User.withDefaultPasswordEncoder()
        .username("admin")
        .password("password")
        .roles("ADMIN").build();
    // @formatter:on

    return new InMemoryUserDetailsManager(user);
  }
  @Bean
  public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
    return http.getSharedObject(AuthenticationManagerBuilder.class).build();
  }

  @Bean
  public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
    UserInfoRepository userInfoRepository = new UserInfoRepository();

    return (context) -> {
      if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
        Authentication authentication = context.getPrincipal();
        Object principal = authentication.getPrincipal();

        String uniqueIdentifier;
        if (principal instanceof UserDetails) {
          uniqueIdentifier = ((UserDetails) principal).getUsername();
        }else {
          throw new IllegalArgumentException("Unknown principal type");
        }

        Map<String, Object> userInfo = ((UserInfoRepository) userInfoRepository).findByUsername(uniqueIdentifier);

        context.getClaims().claims((claimsMap) -> {
          // Add roles to the claims
          Set<String> roles = AuthorityUtils.authorityListToSet(authentication.getAuthorities())
                  .stream()
                  .map(role -> role.replaceFirst("^ROLE_", ""))
                  .collect(Collectors.toSet());
          claimsMap.put("roles", roles);

          // Add email to the claims
          if (userInfo != null && userInfo.containsKey("email")) {
            claimsMap.put("email", userInfo.get("email"));
          }

          // Add profile to the claims
          if (userInfo != null && userInfo.containsKey("profile")) {
            claimsMap.put("profile", userInfo.get("profile"));
          }
        });
      }
    };
  }
}
