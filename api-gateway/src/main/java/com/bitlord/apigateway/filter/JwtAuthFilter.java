package com.bitlord.apigateway.filter;

import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Global JWT Authentication Filter for the API Gateway.
 * Intercepts every incoming request and validates the JWT token
 * before allowing it to reach any downstream microservice.
 */
@Component
public class JwtAuthFilter implements GlobalFilter, Ordered {

    // Utility class that handles JWT token validation and claims extraction
    @Autowired
    private JwtUtil jwtUtil;

    // Paths that bypass JWT validation
    private static final List<String> PUBLIC_PATHS = List.of(
            "/auth/register", "/auth/login", "/auth/refresh"
    );

    /**
     * Main filter logic that runs on every request passing through the gateway.
     *
     * @param exchange - holds the HTTP request and response
     * @param chain    - the next filter in the gateway filter chain
     * @return Mono<Void> - either passes the request forward or short-circuits with 401
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        // Get the request URL path (e.g. "/auth/login" or "/orders/123")
        String path = exchange.getRequest().getURI().getPath();

        // 1. Skip public paths — no JWT required for register, login, refresh
        if (PUBLIC_PATHS.stream().anyMatch(path::contains)) {
            return chain.filter(exchange);
        }

        // 2. Check if the Authorization header is present in the request
        if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
            // No Authorization header found — reject with 401 Unauthorized
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // Extract the raw value of the Authorization header (e.g. "Bearer eyJhbGci...")
        String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            // Strip the "Bearer " prefix to get the raw JWT token string
            authHeader = authHeader.substring(7);
        } else {
            // Authorization header exists but is not in the expected "Bearer <token>" format
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        try {
            // 3. Validate the JWT token — throws an exception if expired or tampered
            jwtUtil.validateToken(authHeader);

            // 4. Extract the claims (payload data) embedded inside the JWT
            Claims claims = jwtUtil.getClaims(authHeader);

            // Pull out userId and role from the token claims
            String userId = claims.get("userId").toString();
            String role = claims.get("role").toString();

            // Inject userId and role as custom headers so downstream services
            // can identify who made the request without re-validating the token
            exchange = exchange.mutate()
                    .request(r -> r.header("X-User-Id", userId)
                            .header("X-User-Role", role))
                    .build();

        } catch (Exception e) {
            // 5. Token is invalid, expired, or malformed — reject with 401 Unauthorized
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // All checks passed — forward the (now enriched) request to the next filter or service
        return chain.filter(exchange);
    }

    /**
     * Sets the execution order of this filter.
     * -1 ensures this filter runs before all other filters in the chain.
     */
    @Override
    public int getOrder() {
        return -1;
    }
}
