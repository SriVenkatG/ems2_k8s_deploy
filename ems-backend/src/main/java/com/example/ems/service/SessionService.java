package com.example.ems.service;

import com.example.ems.dto.SessionDTO;
import java.util.List;

public interface SessionService {
    SessionDTO createSession(Long eventId, SessionDTO dto);
    SessionDTO updateSession(Long eventId, Long sessionId, SessionDTO dto);
    void deleteSession(Long eventId, Long sessionId);
    List<SessionDTO> listByEvent(Long eventId);
}
