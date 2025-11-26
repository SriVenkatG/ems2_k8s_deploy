package com.example.ems.service;

import com.example.ems.config.JwtService;
import com.example.ems.dto.AuthRequest;
import com.example.ems.dto.AuthResponse;
import com.example.ems.model.Role;
import com.example.ems.model.User;
import com.example.ems.repository.RoleRepository;
import com.example.ems.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public class AuthService {

    private final UserRepository userRepo;
    private final RoleRepository roleRepo;
    private final PasswordEncoder encoder;
    private final JwtService jwtService;

    public AuthService(UserRepository userRepo,
                       RoleRepository roleRepo,
                       PasswordEncoder encoder,
                       JwtService jwtService) {
        this.userRepo = userRepo;
        this.roleRepo = roleRepo;
        this.encoder = encoder;
        this.jwtService = jwtService;
    }

    public AuthResponse register(AuthRequest req, String roleName) {
        if (userRepo.existsByEmail(req.getEmail())) {
            throw new RuntimeException("Email exists");
        }

        User user = new User();
        user.setEmail(req.getEmail());
        user.setFullName(req.getFullName());
        user.setPassword(encoder.encode(req.getPassword()));

        Role role = roleRepo.findByName(roleName)
                .orElseThrow(() -> new RuntimeException("Role not found: " + roleName));

        user.setRoles(Set.of(role));
        userRepo.save(user);

        String token = jwtService.generateToken(user.getEmail());
        return new AuthResponse(token, role.getName());
    }

    public AuthResponse login(AuthRequest req) {
        User user = userRepo.findByEmail(req.getEmail())
                .orElseThrow(() -> new RuntimeException("Invalid credentials"));

        if (!encoder.matches(req.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }

        String token = jwtService.generateToken(user.getEmail());
        String roleName = user.getRoles().stream()
                .findAny()
                .map(Role::getName)
                .orElse("ROLE_ATTENDEE");

        return new AuthResponse(token, roleName);
    }
}
