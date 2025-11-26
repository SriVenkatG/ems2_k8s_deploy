package com.example.ems.controller;

import com.example.ems.dto.CreateEventRequest;
import com.example.ems.model.Event;
import com.example.ems.model.TicketType;
import com.example.ems.service.EventService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/api/events")
public class EventController {

    private final EventService eventService;
    public EventController(EventService eventService) {
        this.eventService = eventService;
    }

    // Public: list published events
    @GetMapping
    public List<Event> listPublished() {
        return eventService.listAllPublished();
    }

    // Public: get event details
    @GetMapping("/{id}")
    public ResponseEntity<Event> get(@PathVariable Long id) {
        Event ev = eventService.get(id);
        if (ev == null) return ResponseEntity.notFound().build();
        return ResponseEntity.ok(ev);
    }

    // Public: ticket types for event
    @GetMapping("/{id}/ticket-types")
    public ResponseEntity<Set<TicketType>> getTicketTypes(@PathVariable Long id) {
        Set<TicketType> types = eventService.getTicketTypesForEvent(id);
        if (types == null) return ResponseEntity.notFound().build();
        return ResponseEntity.ok(types);
    }

    // Create event — only ADMIN or ORGANIZER can call
    // Use a DTO so client cannot set organizer directly
    @PreAuthorize("hasRole('ADMIN') or hasRole('ORGANIZER')")
    @PostMapping
    public ResponseEntity<?> create(@RequestBody CreateEventRequest req, Authentication auth) {
        try {
            // pass authenticated user's email (may be null for system/admin flows)
            String email = auth != null ? auth.getName() : null;
            Event created = eventService.createFromDto(req, email);
            return ResponseEntity.ok(created);
        } catch (RuntimeException ex) {
            return ResponseEntity.badRequest().body(ex.getMessage());
        } catch (Exception ex) {
            return ResponseEntity.status(500).body("Server error: " + ex.getMessage());
        }
    }

    // Update with permission check (admin or organizer owner)
    @PreAuthorize("hasRole('ADMIN') or hasRole('ORGANIZER')")
    @PutMapping("/{id}")
    public ResponseEntity<?> updateEvent(@PathVariable Long id, @RequestBody Event updated, Authentication auth) {
        try {
            String email = auth != null ? auth.getName() : null;
            Event saved = eventService.updateEventAsUser(id, updated, email);
            return ResponseEntity.ok(saved);
        } catch (RuntimeException ex) {
            return ResponseEntity.status(400).body(ex.getMessage());
        } catch (Exception ex) {
            return ResponseEntity.status(500).body("Server error: " + ex.getMessage());
        }
    }

    // Delete with permission check
    @PreAuthorize("hasRole('ADMIN') or hasRole('ORGANIZER')")
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteEvent(@PathVariable Long id, Authentication auth) {
        try {
            String email = auth != null ? auth.getName() : null;
            eventService.deleteEventAsUser(id, email);
            return ResponseEntity.ok().body("Deleted");
        } catch (RuntimeException ex) {
            return ResponseEntity.status(400).body(ex.getMessage());
        } catch (Exception ex) {
            return ResponseEntity.status(500).body("Server error: " + ex.getMessage());
        }
    }
}
