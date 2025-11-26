package com.example.ems.service;

import com.example.ems.model.User;
import com.example.ems.repository.UserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final UserRepository userRepository;

    // explicit constructor (no Lombok)
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Return the currently authenticated User entity.
     */
    public User getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getPrincipal())) {
            throw new IllegalStateException("No authenticated user");
        }
        String principalName = auth.getName();
        return userRepository.findByEmail(principalName)
                .orElseThrow(() -> new IllegalStateException("User not found: " + principalName));
    }
}
