package com.huongdanjava.springauthorizationserver.filters;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

public class TenantFilter extends GenericFilterBean {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        String tenantId = servletRequest.getParameter("X-Tenant-Id");
        //boolean hasAccess = isUserAllowed(tenantId);
        boolean hasAccess = true;
        if (hasAccess) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }
        throw new AccessDeniedException("Access denied");
    }
}
