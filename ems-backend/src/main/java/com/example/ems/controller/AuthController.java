package com.example.ems.controller;

import org.springframework.web.bind.annotation.*;
import com.example.ems.service.AuthService;
import com.example.ems.dto.AuthRequest;
import com.example.ems.dto.AuthResponse;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
  private final AuthService authService;
  public AuthController(AuthService authService) { this.authService = authService; }

  @PostMapping("/register")
  public AuthResponse register(@RequestBody AuthRequest req, @RequestParam(defaultValue="ROLE_ATTENDEE") String role) {
    return authService.register(req, role);
  }

  @PostMapping("/login")
  public AuthResponse login(@RequestBody AuthRequest req) {
    return authService.login(req);
  }
}
