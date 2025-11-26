package com.example.ems.controller;

import com.example.ems.model.TicketType;
import com.example.ems.service.EventService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@RestController
@RequestMapping("/api/ticket-types")
public class TicketTypeController {

    private final EventService eventService;

    public TicketTypeController(EventService eventService) {
        this.eventService = eventService;
    }

    /**
     * GET /api/ticket-types?eventId=1
     * Returns ticket types for the given eventId.
     *
     * This mapping avoids conflicting with EventController's
     * GET /api/events/{id}/ticket-types mapping.
     */
    @GetMapping
    public ResponseEntity<Set<TicketType>> getTicketTypes(@RequestParam(name = "eventId", required = true) Long eventId) {
        if (eventId == null) {
            return ResponseEntity.badRequest().build();
        }
        Set<TicketType> types = eventService.getTicketTypesForEvent(eventId);
        if (types == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(types);
    }

    // Add other ticket-type related endpoints here but DO NOT create another mapping
    // that looks like /api/events/{id}/ticket-types (that would clash).
}
