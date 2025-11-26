package com.example.ems.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.ems.service.EmailService;
import com.example.ems.service.UserService;

@RestController
@RequestMapping("/dev")
public class DevController {

    private final EmailService emailService;
    private final UserService userService;

    public DevController(EmailService emailService, UserService userService) {
        this.emailService = emailService;
        this.userService = userService;
    }

    @GetMapping("/test-email")
    public String testEmail() {
        // This will go to your Mailtrap inbox
        emailService.sendSimple("inbox@example.mailtrap.io",
                "Test subject",
                "This is a test email from EMS backend.");
        return "email-sent";
    }

    @GetMapping("/me")
    public String whoami() {
        return userService.getCurrentUser().getEmail();
    }
}
