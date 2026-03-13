package com.secureuserapi.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Request body for the token refresh endpoint.
 *
 * Accepts the refresh token in the request body — the conventional approach.
 * Avoids relying on the Authorization header which is typically reserved
 * for access tokens, and makes the API explicit and easy to test.
 */
public record RefreshRequest(
        @NotBlank(message = "Refresh token must not be blank")
        String refreshToken
) {}
