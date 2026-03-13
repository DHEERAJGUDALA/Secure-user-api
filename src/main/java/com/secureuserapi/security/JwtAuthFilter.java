package com.secureuserapi.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Intercepts every HTTP request exactly once (OncePerRequestFilter).
 *
 * Flow:
 * 1. Extract "Authorization: Bearer <token>" header
 * 2. Extract email from token
 * 3. Load user from DB
 * 4. Validate token (signature, expiry, tokenVersion)
 * 5. Set authentication in SecurityContext → Spring Security knows this request is authenticated
 *
 * If any step fails → do nothing, let Spring Security handle the 401.
 */
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsServiceImpl userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // Skip filter for auth endpoints — they don't have tokens yet
        final String requestPath = request.getServletPath();
        if (requestPath.startsWith("/api/v1/auth/") ||
            requestPath.startsWith("/swagger-ui") ||
            requestPath.startsWith("/v3/api-docs")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extract Authorization header
        final String authHeader = request.getHeader("Authorization");

        // No header or not a Bearer token → skip (Spring Security will block if endpoint is secured)
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extract token (everything after "Bearer ")
        final String jwt = authHeader.substring(7);
        final String userEmail;

        try {
            userEmail = jwtService.extractEmail(jwt);
        } catch (Exception e) {
            // Malformed or tampered token — skip, Spring Security handles 401
            filterChain.doFilter(request, response);
            return;
        }

        // Only authenticate if email extracted AND no authentication already in context
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);

            if (jwtService.isTokenValid(jwt, userDetails)) {
                // Create authentication token — Spring Security uses this internally
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,                          // no credentials needed — JWT is the proof
                                userDetails.getAuthorities()   // roles for authorization
                        );

                // Attach request details (IP, session info) to the auth token
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Store in SecurityContext — this request is now authenticated
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}
