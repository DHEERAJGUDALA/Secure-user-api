package com.secureuserapi.service;

import com.secureuserapi.dto.AuthResponse;
import com.secureuserapi.dto.LoginRequest;
import com.secureuserapi.dto.RegisterRequest;
import com.secureuserapi.entity.User;
import com.secureuserapi.repository.UserRepository;
import com.secureuserapi.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Handles user registration and authentication.
 *
 * Register flow:
 *   1. Check email not already taken
 *   2. Hash the password with BCrypt
 *   3. Save user to DB
 *   4. Generate access + refresh tokens
 *   5. Return AuthResponse
 *
 * Login flow:
 *   1. Delegate credential check to AuthenticationManager
 *      (it calls UserDetailsService → loads user → BCrypt-compares passwords)
 *   2. If valid → generate tokens
 *   3. Return AuthResponse
 *
 * Refresh flow:
 *   1. Validate refresh token
 *   2. Load user from DB
 *   3. Verify tokenVersion matches
 *   4. Issue new access token
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final EmailService emailService;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        // Prevent duplicate accounts
        if (userRepository.existsByEmail(request.email())) {
            throw new IllegalArgumentException(
                    "Email already in use: " + request.email()
            );
        }

        // Build user entity — password is hashed, NEVER stored plain text
        User user = User.builder()
                .firstName(request.firstName())
                .lastName(request.lastName())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .role(request.role())
                .build();

        userRepository.save(user);

        // Fire-and-forget — runs on "async-" thread, HTTP thread continues immediately
        emailService.sendWelcomeEmail(user);

        // Generate tokens immediately after registration — user is logged in
        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        return AuthResponse.of(accessToken, refreshToken, jwtService.getJwtExpiration());
    }

    public AuthResponse login(LoginRequest request) {
        // AuthenticationManager handles the full credential check:
        // loads user via UserDetailsService → BCrypt-compares passwords → throws if invalid
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.email(),
                        request.password()
                )
        );

        // If we reach here → credentials were valid
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new IllegalStateException("User not found after authentication"));

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        return AuthResponse.of(accessToken, refreshToken, jwtService.getJwtExpiration());
    }

    @Transactional
    public AuthResponse refreshToken(String refreshToken) {
        // Extract email from refresh token
        final String email = jwtService.extractEmail(refreshToken);

        if (email == null) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        // Load user and validate the refresh token
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!jwtService.isTokenValid(refreshToken, user)) {
            throw new IllegalArgumentException("Refresh token is invalid or expired");
        }

        // Issue new access token — refresh token stays the same
        String newAccessToken = jwtService.generateAccessToken(user);

        return AuthResponse.of(newAccessToken, refreshToken, jwtService.getJwtExpiration());
    }
}
