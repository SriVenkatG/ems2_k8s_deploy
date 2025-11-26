package com.example.ems.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "bookings")
public class Booking {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Event relationship
    @ManyToOne
    @JoinColumn(name = "event_id")
    private Event event;

    // Attendee (User)
    @ManyToOne
    @JoinColumn(name = "attendee_id")
    private User attendee;

    @Column(name = "ticket_type_name")
    private String ticketTypeName;

    @Column(name = "ticket_code")
    private String ticketCode;

    @Column(name = "checked_in")
    private boolean checkedIn;

    @Column(name = "booked_at")
    private LocalDateTime bookedAt;

    public Booking() {}

    public Long getId() { return id; }

    public Event getEvent() { return event; }
    public void setEvent(Event event) { this.event = event; }

    public User getAttendee() { return attendee; }
    public void setAttendee(User attendee) { this.attendee = attendee; }

    public String getTicketTypeName() { return ticketTypeName; }
    public void setTicketTypeName(String ticketTypeName) { this.ticketTypeName = ticketTypeName; }

    public String getTicketCode() { return ticketCode; }
    public void setTicketCode(String ticketCode) { this.ticketCode = ticketCode; }

    public boolean isCheckedIn() { return checkedIn; }
    public void setCheckedIn(boolean checkedIn) { this.checkedIn = checkedIn; }

    public LocalDateTime getBookedAt() { return bookedAt; }
    public void setBookedAt(LocalDateTime bookedAt) { this.bookedAt = bookedAt; }
}
