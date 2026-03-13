package com.secureuserapi.exception;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Structured error response returned by GlobalExceptionHandler.
 * Every error from this API has this exact shape — consistent, predictable.
 */
public record ErrorResponse(
        int status,
        String error,
        String message,
        String path,
        LocalDateTime timestamp,
        List<String> details       // validation errors, null for single-error responses
) {
    // Factory for simple errors
    public static ErrorResponse of(int status, String error, String message, String path) {
        return new ErrorResponse(status, error, message, path, LocalDateTime.now(), null);
    }

    // Factory for validation errors with multiple detail messages
    public static ErrorResponse ofValidation(int status, String path, List<String> details) {
        return new ErrorResponse(status, "Validation Failed", "Request validation failed",
                path, LocalDateTime.now(), details);
    }
}
