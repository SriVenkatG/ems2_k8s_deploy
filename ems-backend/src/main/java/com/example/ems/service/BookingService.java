package com.example.ems.service;

import com.example.ems.model.*;
import com.example.ems.repository.*;
import com.example.ems.util.QRGenerator;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Objects;
import java.util.UUID;

@Service
public class BookingService {

    private final EventRepository eventRepo;
    private final UserRepository userRepo;
    private final BookingRepository bookingRepo;
    private final TicketTypeRepository ticketTypeRepo;
    private final EmailService emailService; // NEW

    public BookingService(EventRepository eventRepo,
                          UserRepository userRepo,
                          BookingRepository bookingRepo,
                          TicketTypeRepository ticketTypeRepo,
                          EmailService emailService) {
        this.eventRepo = eventRepo;
        this.userRepo = userRepo;
        this.bookingRepo = bookingRepo;
        this.ticketTypeRepo = ticketTypeRepo;
        this.emailService = emailService;
    }

    @Transactional
    public Booking bookFree(Long eventId, Long ticketTypeId, String userEmail) {
        Event event = eventRepo.findById(eventId)
                .orElseThrow(() -> new RuntimeException("Event not found: " + eventId));

        User user = userRepo.findByEmail(userEmail)
                .orElseThrow(() -> new RuntimeException("User not found: " + userEmail));

        TicketType tt = null;
        if (ticketTypeId != null) {
            tt = ticketTypeRepo.findById(ticketTypeId)
                    .orElseThrow(() -> new RuntimeException("TicketType not found: " + ticketTypeId));
            if (tt.getEvent() == null || !Objects.equals(tt.getEvent().getId(), eventId)) {
                throw new RuntimeException("TicketType does not belong to event: " + eventId);
            }
            if (tt.getPrice() != null && tt.getPrice() > 0.0) {
                throw new RuntimeException("Selected ticket is not free. Use paid booking flow.");
            }
        } else if (event.getTicketTypes() != null) {
            tt = event.getTicketTypes().stream()
                    .filter(t -> t.getPrice() == null || t.getPrice() == 0.0)
                    .findFirst()
                    .orElse(null);
        }

        Booking b = new Booking();
        b.setEvent(event);
        b.setAttendee(user);
        b.setTicketTypeName(tt != null ? tt.getName() : null);
        b.setTicketCode(UUID.randomUUID().toString());
        b.setBookedAt(LocalDateTime.now());
        b.setCheckedIn(false);

        Booking saved = bookingRepo.save(b);

        // ✅ Trigger booking confirmation email
        emailService.sendBookingConfirmation(user, event, tt);

        return saved;
    }

    @Transactional(readOnly = true)
    public String getTicketQRCodeBase64(Long bookingId) throws Exception {
        Booking booking = bookingRepo.findById(bookingId)
                .orElseThrow(() -> new RuntimeException("Booking not found: " + bookingId));

        String payload = booking.getTicketCode();
        if (payload == null || payload.isEmpty()) {
            throw new RuntimeException("Booking has no ticket code to encode");
        }
        return QRGenerator.generateQRCodeBase64(payload, 300, 300);
    }

    @Transactional
    public Booking checkIn(Long bookingId) {
        Booking booking = bookingRepo.findById(bookingId)
                .orElseThrow(() -> new RuntimeException("Booking not found: " + bookingId));
        booking.setCheckedIn(true);
        return bookingRepo.save(booking);
    }
}
