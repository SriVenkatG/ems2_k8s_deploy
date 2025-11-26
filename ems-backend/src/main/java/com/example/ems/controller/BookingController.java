package com.example.ems.controller;

import org.springframework.web.bind.annotation.*;
import com.example.ems.service.BookingService;
import com.example.ems.model.Booking;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;

@RestController
@RequestMapping("/api/bookings")
public class BookingController {
  private final BookingService bookingService;
  public BookingController(BookingService bookingService) { this.bookingService = bookingService; }

  @PostMapping("/free")
  public Booking bookFree(@RequestParam Long eventId,
                          @RequestParam(required = false) Long ticketTypeId,
                          @AuthenticationPrincipal UserDetails user) throws Exception {
      return bookingService.bookFree(eventId, ticketTypeId, user.getUsername());
  }

  @GetMapping("/{id}/qrcode")
  public String getQRCode(@PathVariable Long id) throws Exception {
    return bookingService.getTicketQRCodeBase64(id); // base64 PNG string
  }

  @PostMapping("/{id}/checkin")
  public Booking checkIn(@PathVariable Long id) {
    return bookingService.checkIn(id);
  }
}
