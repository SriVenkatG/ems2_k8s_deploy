package com.example.ems.repository;

import com.example.ems.model.Session;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface SessionRepository extends JpaRepository<Session, Long> {
    List<Session> findByEventIdOrderByStartTime(Long eventId);
}