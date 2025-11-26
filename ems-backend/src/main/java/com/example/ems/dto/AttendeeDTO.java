package com.example.ems.dto;

import java.time.LocalDateTime;

public class AttendeeDTO {
    private Long userId;
    private String email;
    private String fullName;
    private LocalDateTime registeredAt;

    public AttendeeDTO(Long userId, String email, String fullName, LocalDateTime registeredAt) {
        this.userId = userId;
        this.email = email;
        this.fullName = fullName;
        this.registeredAt = registeredAt;
    }

    public Long getUserId() { return userId; }
    public String getEmail() { return email; }
    public String getFullName() { return fullName; }
    public LocalDateTime getRegisteredAt() { return registeredAt; }
}
