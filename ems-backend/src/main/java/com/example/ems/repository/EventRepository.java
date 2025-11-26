// src/main/java/com/example/ems/repository/EventRepository.java
package com.example.ems.repository;

import com.example.ems.model.Event;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;

public interface EventRepository extends JpaRepository<Event, Long> {
    List<Event> findByPublishedTrue();

    // ✅ New method to fetch upcoming events within a time range
    List<Event> findByStartTimeBetween(LocalDateTime start, LocalDateTime end);
}
