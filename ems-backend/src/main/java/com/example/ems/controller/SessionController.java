package com.example.ems.controller;

import com.example.ems.dto.SessionDTO;
import com.example.ems.service.SessionService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/events/{eventId}/sessions")
public class SessionController {

    private final SessionService sessionService;

    public SessionController(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    @GetMapping
    public ResponseEntity<List<SessionDTO>> list(@PathVariable Long eventId) {
        return ResponseEntity.ok(sessionService.listByEvent(eventId));
    }

    @PreAuthorize("hasAnyRole('ORGANIZER','ADMIN')")
    @PostMapping
    public ResponseEntity<SessionDTO> create(@PathVariable Long eventId, @RequestBody SessionDTO dto) {
        SessionDTO created = sessionService.createSession(eventId, dto);
        return ResponseEntity.ok(created);
    }

    @PreAuthorize("hasAnyRole('ORGANIZER','ADMIN')")
    @PutMapping("/{sessionId}")
    public ResponseEntity<SessionDTO> update(@PathVariable Long eventId,
                                             @PathVariable Long sessionId,
                                             @RequestBody SessionDTO dto) {
        SessionDTO updated = sessionService.updateSession(eventId, sessionId, dto);
        return ResponseEntity.ok(updated);
    }

    @PreAuthorize("hasAnyRole('ORGANIZER','ADMIN')")
    @DeleteMapping("/{sessionId}")
    public ResponseEntity<Void> delete(@PathVariable Long eventId,
                                       @PathVariable Long sessionId) {
        sessionService.deleteSession(eventId, sessionId);
        return ResponseEntity.noContent().build();
    }
}
