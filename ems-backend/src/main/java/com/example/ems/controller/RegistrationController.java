package com.example.ems.controller;

import com.example.ems.model.Registration;
import com.example.ems.service.RegistrationService;
import com.example.ems.dto.AttendeeDTO;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/events")
public class RegistrationController {
    private final RegistrationService registrationService;

    public RegistrationController(RegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    @PostMapping("/{eventId}/register")
    public ResponseEntity<?> register(@PathVariable Long eventId, Authentication auth) {
        if (auth == null || auth.getName() == null) {
            return ResponseEntity.status(401).body("Unauthorized");
        }
        String email = auth.getName(); // principal is email
        try {
            registrationService.registerUserToEvent(eventId, email);
            return ResponseEntity.ok("Registered successfully");
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(ex.getMessage());
        } catch (Exception ex) {
            return ResponseEntity.status(500).body("Server error: " + ex.getMessage());
        }
    }

    // ✅ Only ADMIN and ORGANIZER can view attendees
    @PreAuthorize("hasRole('ADMIN') or hasRole('ORGANIZER')")
    @GetMapping("/{eventId}/attendees")
    public ResponseEntity<?> attendees(@PathVariable Long eventId) {
        try {
            List<Registration> regs = registrationService.getRegistrationsForEvent(eventId);
            List<AttendeeDTO> dtos = regs.stream().map(r ->
                new AttendeeDTO(
                    r.getUser().getId(),
                    r.getUser().getEmail(),
                    r.getUser().getFullName() != null ? r.getUser().getFullName() : "",
                    r.getRegisteredAt()
                )
            ).collect(Collectors.toList());
            return ResponseEntity.ok(dtos);
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(ex.getMessage());
        } catch (Exception ex) {
            return ResponseEntity.status(500).body("Server error: " + ex.getMessage());
        }
    }
    // ✅ Check if the logged-in user is registered for this event
    @GetMapping("/{eventId}/status")
    public ResponseEntity<?> registrationStatus(@PathVariable Long eventId, Authentication auth) {
        if (auth == null || auth.getName() == null) {
            return ResponseEntity.status(401).body("Unauthorized");
        }
        String email = auth.getName();
        try {
            boolean registered = registrationService.isUserRegistered(eventId, email);
            return ResponseEntity.ok().body(java.util.Map.of("registered", registered));
        } catch (Exception ex) {
            return ResponseEntity.status(500).body("Server error: " + ex.getMessage());
        }
    }

}
