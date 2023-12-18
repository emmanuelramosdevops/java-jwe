package com.crypto.jwe.web.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

@Component
public class TracingFilter extends OncePerRequestFilter {

    private final ThreadLocal<String> traceId = new ThreadLocal<>();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        try {
            traceId.set(UUID.randomUUID().toString());

            MDC.put("traceId", traceId.get());

            chain.doFilter(request, response);
        } finally {
            traceId.remove();
        }
    }
}