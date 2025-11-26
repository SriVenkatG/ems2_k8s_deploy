package com.example.ems.service;

import com.example.ems.model.Event;
import com.example.ems.model.Registration;
import com.example.ems.model.User;
import com.example.ems.repository.EventRepository;
import com.example.ems.repository.RegistrationRepository;
import com.example.ems.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class RegistrationService {
    private final RegistrationRepository registrationRepository;
    private final EventRepository eventRepository;
    private final UserRepository userRepository;
    private final EmailService emailService; // NEW

    public RegistrationService(RegistrationRepository registrationRepository,
                               EventRepository eventRepository,
                               UserRepository userRepository,
                               EmailService emailService) {
        this.registrationRepository = registrationRepository;
        this.eventRepository = eventRepository;
        this.userRepository = userRepository;
        this.emailService = emailService;
    }

    @Transactional
    public Registration registerUserToEvent(Long eventId, String email) {
        Event event = eventRepository.findById(eventId)
            .orElseThrow(() -> new IllegalArgumentException("Event not found"));

        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (registrationRepository.findByUserAndEvent(user, event).isPresent()) {
            throw new IllegalArgumentException("Already registered");
        }

        Registration reg = new Registration(user, event);
        Registration saved = registrationRepository.save(reg);

        // ✅ Trigger confirmation email
        emailService.sendRegistrationConfirmation(user, event);

        return saved;
    }

    public List<Registration> getRegistrationsForEvent(Long eventId) {
        Event event = eventRepository.findById(eventId)
            .orElseThrow(() -> new IllegalArgumentException("Event not found"));
        return registrationRepository.findByEvent(event);
    }

    public long countRegistrations(Long eventId) {
        Event event = eventRepository.findById(eventId)
            .orElseThrow(() -> new IllegalArgumentException("Event not found"));
        return registrationRepository.countByEvent(event);
    }

    public boolean isUserRegistered(Long eventId, String email) {
        Event event = eventRepository.findById(eventId)
            .orElseThrow(() -> new IllegalArgumentException("Event not found"));
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new IllegalArgumentException("User not found"));
        return registrationRepository.findByUserAndEvent(user, event).isPresent();
    }
}
