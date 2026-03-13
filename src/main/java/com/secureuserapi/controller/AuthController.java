package com.secureuserapi.controller;

import com.secureuserapi.dto.AuthResponse;
import com.secureuserapi.dto.LoginRequest;
import com.secureuserapi.dto.RefreshRequest;
import com.secureuserapi.dto.RegisterRequest;
import com.secureuserapi.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Authentication endpoints — all public (no JWT required).
 * Configured as permitAll() in SecurityConfig.
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Register, login and refresh token endpoints")
public class AuthController {

    private final AuthService authService;

    /**
     * Register a new user.
     * Returns JWT tokens immediately — user is logged in after registration.
     */
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Register a new user", description = "Creates account and returns JWT tokens")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(authService.register(request));
    }

    /**
     * Login with email + password.
     * Returns JWT tokens on success.
     */
    @PostMapping("/login")
    @Operation(summary = "Login", description = "Authenticate with email/password, returns JWT tokens")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    /**
     * Refresh access token using a valid refresh token.
     * Client sends refresh token in the request body.
     *
     * Design note: accepting the refresh token in the request body is the
     * conventional approach (used by Google, Auth0, etc.). The Authorization
     * header is reserved for access tokens.
     */
    @PostMapping("/refresh")
    @Operation(summary = "Refresh token", description = "Get new access token using refresh token")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        return ResponseEntity.ok(authService.refreshToken(request.refreshToken()));
    }
}
