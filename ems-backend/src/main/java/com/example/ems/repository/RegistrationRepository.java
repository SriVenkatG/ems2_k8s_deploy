package com.example.ems.repository;

import com.example.ems.model.Registration;
import com.example.ems.model.Event;
import com.example.ems.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RegistrationRepository extends JpaRepository<Registration, Long> {
    List<Registration> findByEvent(Event event);
    Optional<Registration> findByUserAndEvent(User user, Event event);
    long countByEvent(Event event);

    // NEW: find only registrations that have not yet been sent reminders
    List<Registration> findByEventAndReminderSentFalse(Event event);
}
