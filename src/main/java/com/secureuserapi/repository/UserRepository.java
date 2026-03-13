package com.secureuserapi.repository;

import com.secureuserapi.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // Used by UserDetailsServiceImpl to load user during JWT validation
    Optional<User> findByEmail(String email);

    // Used by AuthService during registration to prevent duplicate accounts
    boolean existsByEmail(String email);
}
