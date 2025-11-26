package com.example.ems.service;

import com.example.ems.dto.SessionDTO;
import com.example.ems.model.Event;
import com.example.ems.model.Session;
import com.example.ems.repository.EventRepository;
import com.example.ems.repository.SessionRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class SessionServiceImpl implements SessionService {

    private final SessionRepository sessionRepository;
    private final EventRepository eventRepository;

    public SessionServiceImpl(SessionRepository sessionRepository, EventRepository eventRepository) {
        this.sessionRepository = sessionRepository;
        this.eventRepository = eventRepository;
    }

    private SessionDTO toDto(Session s) {
        SessionDTO dto = new SessionDTO();
        dto.setId(s.getId());
        dto.setEventId(s.getEventId());
        dto.setTitle(s.getTitle());
        dto.setDescription(s.getDescription());
        dto.setSpeaker(s.getSpeaker());
        dto.setLocation(s.getLocation());
        dto.setStartTime(s.getStartTime() != null ? s.getStartTime().toString() : null);
        dto.setEndTime(s.getEndTime() != null ? s.getEndTime().toString() : null);
        return dto;
    }

    private Session fromDto(SessionDTO dto) {
        Session s = new Session();
        s.setTitle(dto.getTitle());
        s.setDescription(dto.getDescription());
        s.setSpeaker(dto.getSpeaker());
        s.setLocation(dto.getLocation());
        if (dto.getStartTime() != null) s.setStartTime(LocalDateTime.parse(dto.getStartTime()));
        if (dto.getEndTime() != null) s.setEndTime(LocalDateTime.parse(dto.getEndTime()));
        return s;
    }

    @Override
    @Transactional
    public SessionDTO createSession(Long eventId, SessionDTO dto) {
        // check event exists
        Optional<Event> evOpt = eventRepository.findById(eventId);
        if (!evOpt.isPresent()) {
            throw new IllegalArgumentException("Event not found: " + eventId);
        }

        Session s = fromDto(dto);
        s.setEventId(eventId);
        Session saved = sessionRepository.save(s);
        return toDto(saved);
    }

    @Override
    @Transactional
    public SessionDTO updateSession(Long eventId, Long sessionId, SessionDTO dto) {
        Session s = sessionRepository.findById(sessionId)
                .orElseThrow(() -> new IllegalArgumentException("Session not found: " + sessionId));
        if (!s.getEventId().equals(eventId)) {
            throw new IllegalArgumentException("Session does not belong to event");
        }
        // update fields
        s.setTitle(dto.getTitle());
        s.setDescription(dto.getDescription());
        s.setSpeaker(dto.getSpeaker());
        s.setLocation(dto.getLocation());
        if (dto.getStartTime() != null) s.setStartTime(LocalDateTime.parse(dto.getStartTime()));
        if (dto.getEndTime() != null) s.setEndTime(LocalDateTime.parse(dto.getEndTime()));
        Session updated = sessionRepository.save(s);
        return toDto(updated);
    }

    @Override
    @Transactional
    public void deleteSession(Long eventId, Long sessionId) {
        Session s = sessionRepository.findById(sessionId)
                .orElseThrow(() -> new IllegalArgumentException("Session not found: " + sessionId));
        if (!s.getEventId().equals(eventId)) {
            throw new IllegalArgumentException("Session does not belong to event");
        }
        sessionRepository.delete(s);
    }

    @Override
    public List<SessionDTO> listByEvent(Long eventId) {
        List<Session> sessions = sessionRepository.findByEventIdOrderByStartTime(eventId);
        return sessions.stream().map(this::toDto).collect(Collectors.toList());
    }
}
