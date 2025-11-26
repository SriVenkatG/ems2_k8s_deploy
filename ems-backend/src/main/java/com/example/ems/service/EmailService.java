package com.example.ems.service;

import com.example.ems.model.Event;
import com.example.ems.model.TicketType;
import com.example.ems.model.User;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private final JavaMailSender mailSender;

    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Async
    public void sendRegistrationConfirmation(User user, Event event) {
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(user.getEmail());
        msg.setSubject("Registration confirmed: " + event.getTitle());
        msg.setText("Hello " + user.getFullName() + ",\n\n" +
                "You have successfully registered for the event:\n" +
                event.getTitle() + "\n" +
                "Location: " + event.getLocation() + "\n" +
                "Start: " + event.getStartTime() + "\n" +
                "End: " + event.getEndTime() + "\n\n" +
                "Thank you!\nEvent Management System");
        mailSender.send(msg);
    }

    @Async
    public void sendBookingConfirmation(User user, Event event, TicketType ticketType) {
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(user.getEmail());
        msg.setSubject("Booking confirmed: " + event.getTitle());
        msg.setText("Hello " + user.getFullName() + ",\n\n" +
                "Your booking is confirmed for:\n" +
                event.getTitle() + "\n" +
                "Ticket type: " + (ticketType != null ? ticketType.getName() : "General") + "\n" +
               
                "Location: " + event.getLocation() + "\n" +
                "Start: " + event.getStartTime() + "\n" +
                "End: " + event.getEndTime() + "\n\n" +
                "Please bring this email or your QR code for entry.\n\n" +
                "Thank you!\nEvent Management System");
        mailSender.send(msg);
    }

    @Async
    public void sendReminder(User user, Event event) {
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(user.getEmail());
        msg.setSubject("Reminder: " + event.getTitle() + " is coming soon!");
        msg.setText("Hello " + user.getFullName() + ",\n\n" +
                "This is a reminder that the event:\n" +
                event.getTitle() + "\n" +
                "will start at: " + event.getStartTime() + "\n" +
                "Location: " + event.getLocation() + "\n\n" +
                "See you there!\nEvent Management System");
        mailSender.send(msg);
    }

    // ✨ Utility for DevController test
    @Async
    public void sendSimple(String to, String subject, String body) {
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(to);
        msg.setSubject(subject);
        msg.setText(body);
        mailSender.send(msg);
    }
}
