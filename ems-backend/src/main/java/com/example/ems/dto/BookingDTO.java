package com.example.ems.dto;

import lombok.Data;

@Data
public class BookingDTO {
    private Long eventId;
    private Long ticketTypeId;
    private String userEmail;
}
