package com.example.ems.dto;

import lombok.Data;
import java.time.LocalDateTime;
import java.util.List;

@Data
public class EventDTO {
    private Long id;
    private String title;
    private String description;
    private String venue;
    private LocalDateTime startAt;
    private LocalDateTime endAt;
    private boolean published;
    private List<TicketTypeDTO> ticketTypes;
}

@Data
class TicketTypeDTO {
    private Long id;
    private String name;
    private Integer capacity;
    private Double price;
}
