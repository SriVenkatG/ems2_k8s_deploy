package com.example.ems.controller;

import com.example.ems.model.Booking;
import com.example.ems.repository.BookingRepository;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/organizer")
public class OrganizerController {

    private final BookingRepository bookingRepo;

    public OrganizerController(BookingRepository bookingRepo) {
        this.bookingRepo = bookingRepo;
    }

    @GetMapping("/events/{eventId}/attendees/export")
    public void exportAttendees(@PathVariable Long eventId, HttpServletResponse response) throws IOException {
        response.setContentType("text/csv");
        String filename = "attendees_event_" + eventId + ".csv";
        response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");

        List<Booking> bookings = bookingRepo.findByEventId(eventId);

        try (CSVPrinter printer = new CSVPrinter(response.getWriter(),
                CSVFormat.DEFAULT.withHeader("BookingId", "AttendeeEmail", "TicketType", "CheckedIn", "BookedAt"))) {

            for (Booking b : bookings) {
                String attendeeEmail = b.getAttendee() != null ? b.getAttendee().getEmail() : "";
                String ticketType = b.getTicketTypeName() != null ? b.getTicketTypeName() : "";
                printer.printRecord(b.getId(), attendeeEmail, ticketType, b.isCheckedIn(), b.getBookedAt());
            }
            printer.flush();
        }
    }

    @GetMapping("/events/{eventId}/summary")
    public Map<String, Object> eventSummary(@PathVariable Long eventId) {
        long total = bookingRepo.countByEventId(eventId);
        long checkedIn = bookingRepo.countByEventIdAndCheckedInTrue(eventId);
        return Map.of("totalBookings", total, "checkedIn", checkedIn);
    }
}
