package com.example.ems.model;

import jakarta.persistence.*;
import java.io.Serializable;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * TicketType entity - belongs to an Event
 */
@Entity
@Table(name = "ticket_types")
@JsonIgnoreProperties({"hibernateLazyInitializer","handler"})
public class TicketType implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;    // e.g. "General Admission"
    private Double price;   // null or 0.0 = free

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "event_id")
    private Event event;

    public TicketType() {}

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public Double getPrice() { return price; }
    public void setPrice(Double price) { this.price = price; }

    public Event getEvent() { return event; }
    public void setEvent(Event event) { this.event = event; }
}
