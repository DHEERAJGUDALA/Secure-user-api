package com.secureuserapi.controller;

import com.secureuserapi.dto.UserResponse;
import com.secureuserapi.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * User management endpoints — all require authentication.
 * Role-based access enforced with @PreAuthorize.
 *
 * ADMIN can: get all users, get user by id, delete user
 * Any authenticated user can: get their own profile
 */
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Tag(name = "User Management", description = "User profile and admin operations")
@SecurityRequirement(name = "bearerAuth")  // Tells Swagger UI to send Bearer token
public class UserController {

    private final UserService userService;

    /**
     * Get all users — ADMIN only.
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Get all users", description = "ADMIN only — returns all registered users")
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    /**
     * Get currently authenticated user's profile.
     * Any authenticated user (USER, ADMIN, MANAGER) can access this.
     */
    @GetMapping("/me")
    @Operation(summary = "Get my profile", description = "Returns the authenticated user's own profile")
    public ResponseEntity<UserResponse> getCurrentUser() {
        return ResponseEntity.ok(userService.getCurrentUser());
    }

    /**
     * Get user by ID — ADMIN or MANAGER.
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    @Operation(summary = "Get user by ID", description = "ADMIN/MANAGER only")
    public ResponseEntity<UserResponse> getUserById(@PathVariable Long id) {
        return ResponseEntity.ok(userService.getUserById(id));
    }

    /**
     * Delete user — ADMIN only.
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Delete user", description = "ADMIN only — permanently deletes a user")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}
