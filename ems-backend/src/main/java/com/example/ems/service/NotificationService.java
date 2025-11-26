package com.example.ems.service;

import com.example.ems.model.Event;
import com.example.ems.model.Registration;
import com.example.ems.repository.EventRepository;
import com.example.ems.repository.RegistrationRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class NotificationService {

    private final EventRepository eventRepository;
    private final RegistrationRepository registrationRepository;
    private final EmailService emailService;

    public NotificationService(EventRepository eventRepository,
                               RegistrationRepository registrationRepository,
                               EmailService emailService) {
        this.eventRepository = eventRepository;
        this.registrationRepository = registrationRepository;
        this.emailService = emailService;
    }

    /**
     * Runs every hour (on the hour).
     * Finds events whose reminder time has come and sends ONE reminder email per registration.
     */
    @Scheduled(cron = "0 0 * * * ?")
    public void sendReminders() {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime windowEnd = now.plusHours(1);

        // look at events starting soon (within the next 2 days)
        List<Event> upcomingEvents = eventRepository.findByStartTimeBetween(now.minusHours(1), now.plusDays(2));

        for (Event event : upcomingEvents) {
            int offset = (event.getReminderOffsetMinutes() != null ? event.getReminderOffsetMinutes() : 1440);
            LocalDateTime reminderTime = event.getStartTime().minusMinutes(offset);

            // check if we are in the reminder window (this hour)
            if (!now.isBefore(reminderTime) && now.isBefore(reminderTime.plusHours(1))) {
                List<Registration> regs = registrationRepository.findByEventAndReminderSentFalse(event);
                for (Registration r : regs) {
                    emailService.sendReminder(r.getUser(), event);
                    r.setReminderSent(true);
                    r.setReminderSentAt(LocalDateTime.now());
                    registrationRepository.save(r);
                }
            }
        }
    }
}
