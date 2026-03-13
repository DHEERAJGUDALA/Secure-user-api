package com.secureuserapi.service;

import com.secureuserapi.dto.UserResponse;
import com.secureuserapi.entity.User;
import com.secureuserapi.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Handles user management operations.
 *
 * Two categories of operations:
 * 1. Admin-only: getAllUsers, getUserById, deleteUser
 * 2. Self-service: getCurrentUser (any authenticated user can fetch their own profile)
 *
 * Note: endpoint-level security is in SecurityConfig + @PreAuthorize on controllers.
 * Service layer adds extra self-ownership check for profile access.
 */
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    /**
     * Get all users — ADMIN only.
     * Controller enforces this with @PreAuthorize.
     */
    @Transactional(readOnly = true)
    public List<UserResponse> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .map(UserResponse::from)
                .toList();
    }

    /**
     * Get user by ID — ADMIN only.
     */
    @Transactional(readOnly = true)
    public UserResponse getUserById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + id));
        return UserResponse.from(user);
    }

    /**
     * Get currently authenticated user's own profile.
     * Any authenticated user can call this — no role restriction.
     */
    @Transactional(readOnly = true)
    public UserResponse getCurrentUser() {
        // Extract email from SecurityContext — set by JwtAuthFilter
        String email = SecurityContextHolder.getContext()
                .getAuthentication()
                .getName();

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found in DB"));

        return UserResponse.from(user);
    }

    /**
     * Delete user — ADMIN only.
     * An ADMIN cannot delete themselves (safety guard).
     */
    @Transactional
    public void deleteUser(Long id) {
        String currentUserEmail = SecurityContextHolder.getContext()
                .getAuthentication()
                .getName();

        User userToDelete = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + id));

        // Prevent admin from deleting their own account
        if (userToDelete.getEmail().equals(currentUserEmail)) {
            throw new AccessDeniedException("You cannot delete your own account");
        }

        userRepository.delete(userToDelete);
    }
}
