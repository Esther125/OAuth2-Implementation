package com.huongdanjava.springauthorizationserver.filters;

import com.huongdanjava.springauthorizationserver.RateLimitingService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class RateLimitFilter extends OncePerRequestFilter {
    private final RateLimitingService rateLimitingService = new RateLimitingService();

    @Override
    protected void doFilterInternal(HttpServletRequest servletRequest, HttpServletResponse servletResponse, FilterChain filterChain) throws ServletException, IOException {

        final var authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean shouldContinue = true;

        if (authentication != null) {
            Object details = authentication.getDetails();
            String ipAddress = null;
            if (details instanceof WebAuthenticationDetails) {
                WebAuthenticationDetails webDetails = (WebAuthenticationDetails) details;
                ipAddress = webDetails.getRemoteAddress();
            }

            final Bucket tokenBucket = rateLimitingService.resolveBucket(ipAddress);
            final ConsumptionProbe probe = tokenBucket.tryConsumeAndReturnRemaining(1);

            if (!probe.isConsumed()) {
                ((HttpServletResponse) servletResponse).sendError(HttpStatus.TOO_MANY_REQUESTS.value(), "Request limit linked to your current plan has been exhausted");
                shouldContinue = false;
            }
        }

        if (shouldContinue) {
            filterChain.doFilter(servletRequest, servletResponse);
        }
    }
}
