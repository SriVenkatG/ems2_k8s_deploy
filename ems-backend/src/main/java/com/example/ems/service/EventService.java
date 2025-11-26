package com.example.ems.service;

import com.example.ems.dto.CreateEventRequest;
import com.example.ems.model.Event;
import com.example.ems.model.TicketType;
import com.example.ems.model.User;
import com.example.ems.repository.EventRepository;
import com.example.ems.repository.TicketTypeRepository;
import com.example.ems.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;

@Service
public class EventService {

    private final EventRepository eventRepository;
    private final UserRepository userRepository;
    private final TicketTypeRepository ticketTypeRepository;

    public EventService(EventRepository eventRepository,
                        UserRepository userRepository,
                        TicketTypeRepository ticketTypeRepository) {
        this.eventRepository = eventRepository;
        this.userRepository = userRepository;
        this.ticketTypeRepository = ticketTypeRepository;
    }

    // ---------- Read operations ----------

    public List<Event> listAllPublished() {
        // returns published events (your EventRepository should have findByPublishedTrue)
        return eventRepository.findByPublishedTrue();
    }

    public Event get(Long id) {
        return eventRepository.findById(id).orElse(null);
    }

    public Set<TicketType> getTicketTypesForEvent(Long id) {
        Event e = eventRepository.findById(id).orElse(null);
        return e == null ? null : e.getTicketTypes();
    }

    // ---------- Create ----------

    /**
     * Create event from DTO and optionally set organizer by email.
     * If userEmail is null, the event will be created without organizer.
     */
    @Transactional
    public Event createFromDto(CreateEventRequest req, String userEmail) {
        Event e = new Event();
        e.setTitle(req.getTitle());
        e.setDescription(req.getDescription());
        e.setLocation(req.getLocation());
        e.setStartTime(req.getStartTime());
        e.setEndTime(req.getEndTime());
        e.setPublished(req.isPublished());

        if (userEmail != null) {
            userRepository.findByEmail(userEmail).ifPresent(e::setOrganizer);
        }

        // If ticket types are part of DTO in future, add mapping here.
        return eventRepository.save(e);
    }

    // ---------- Update (with permission checks) ----------

    /**
     * Update event with permission check: admin or organizer (owner) may update.
     * The 'updates' Event object is used only to carry new values for allowed fields.
     *
     * @param id event id
     * @param updates source event object with updated fields (title, description, location, startTime, endTime, published)
     * @param userEmail email of the authenticated user making the change (may be null for system/admin)
     * @return saved Event
     */
    @Transactional
    public Event updateEventAsUser(Long id, Event updates, String userEmail) {
        Event event = eventRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Event not found: " + id));

        // permission check
        boolean isAdmin = false;
        if (userEmail != null) {
            User u = userRepository.findByEmail(userEmail).orElse(null);
            if (u != null && u.getRoles() != null) {
                isAdmin = u.getRoles().stream().anyMatch(r -> "ROLE_ADMIN".equalsIgnoreCase(r.getName()));
            }
            if (!isAdmin) {
                // must be organizer/owner
                if (event.getOrganizer() == null || u == null || !u.getEmail().equalsIgnoreCase(event.getOrganizer().getEmail())) {
                    throw new RuntimeException("Forbidden: only organizer or admin can edit this event");
                }
            }
        } else {
            // no user provided -> disallow unless you want system flows
            throw new RuntimeException("Unauthorized: no authenticated user");
        }

        // apply allowed updates
        if (updates.getTitle() != null) event.setTitle(updates.getTitle());
        if (updates.getDescription() != null) event.setDescription(updates.getDescription());
        event.setLocation(updates.getLocation()); // allow setting location (nullable)
        event.setStartTime(updates.getStartTime());
        event.setEndTime(updates.getEndTime());
        event.setPublished(updates.isPublished());

        // NOTE: Do NOT overwrite organizer here (unless admin explicitly sets that).
        return eventRepository.save(event);
    }

    // ---------- Delete (with permission checks) ----------

    /**
     * Delete event if requester is admin or organizer (owner).
     */
    @Transactional
    public void deleteEventAsUser(Long eventId, String userEmail) {
        Event event = eventRepository.findById(eventId)
                .orElseThrow(() -> new RuntimeException("Event not found: " + eventId));

        if (userEmail == null) throw new RuntimeException("Unauthorized");

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new RuntimeException("User not found: " + userEmail));

        boolean isAdmin = user.getRoles() != null && user.getRoles().stream()
                .anyMatch(r -> "ROLE_ADMIN".equalsIgnoreCase(r.getName()));

        if (!isAdmin) {
            // must be organizer
            if (event.getOrganizer() == null || !user.getEmail().equalsIgnoreCase(event.getOrganizer().getEmail())) {
                throw new RuntimeException("Forbidden: only organizer or admin can delete this event");
            }
        }

        eventRepository.delete(event);
    }
}
