package com.example.ems.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import com.example.ems.repository.RoleRepository;
import com.example.ems.repository.UserRepository;
import com.example.ems.model.Role;
import com.example.ems.model.User;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Set;
import java.util.Optional;
import java.util.logging.Logger;

@Component
public class DataInitializer implements CommandLineRunner {

    private static final Logger LOG = Logger.getLogger(DataInitializer.class.getName());

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(RoleRepository roleRepository,
                           UserRepository userRepository,
                           PasswordEncoder passwordEncoder) {
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        // 1) Ensure roles exist
        List<String> roles = List.of("ROLE_ADMIN", "ROLE_ORGANIZER", "ROLE_ATTENDEE");
        for (String rn : roles) {
            Optional<Role> existing = roleRepository.findByName(rn);
            if (existing.isEmpty()) {
                Role r = new Role();
                r.setName(rn);
                roleRepository.save(r);
                LOG.info("Created role: " + rn);
            } else {
                LOG.info("Role exists: " + rn);
            }
        }

        // Helper: get role (we can safely call get() because we just ensured they exist)
        Role adminRole = roleRepository.findByName("ROLE_ADMIN").orElseThrow(() -> new IllegalStateException("ROLE_ADMIN missing"));
        Role organizerRole = roleRepository.findByName("ROLE_ORGANIZER").orElseThrow(() -> new IllegalStateException("ROLE_ORGANIZER missing"));
        Role attendeeRole = roleRepository.findByName("ROLE_ATTENDEE").orElseThrow(() -> new IllegalStateException("ROLE_ATTENDEE missing"));

        // 2) Create default admin if missing
        if (userRepository.findByEmail("admin@example.com").isEmpty()) {
            User u = new User();
            u.setEmail("admin@example.com");
            u.setFullName("System Admin");
            u.setPassword(passwordEncoder.encode("admin123"));
            // Use Java 9+ Set.of; if Java8 replace with Collections.singleton(adminRole)
            u.setRoles(Set.of(adminRole));
            userRepository.save(u);
            LOG.info("Created default admin: admin@example.com / admin123");
        } else {
            LOG.info("Default admin already present");
        }

        // 3) Create default organizer if missing
        if (userRepository.findByEmail("organizer@example.com").isEmpty()) {
            User u = new User();
            u.setEmail("organizer@example.com");
            u.setFullName("Default Organizer");
            u.setPassword(passwordEncoder.encode("organizer123"));
            u.setRoles(Set.of(organizerRole));
            userRepository.save(u);
            LOG.info("Created default organizer: organizer@example.com / organizer123");
        } else {
            LOG.info("Default organizer already present");
        }

        // 4) Create default attendee if missing
        if (userRepository.findByEmail("attendee@example.com").isEmpty()) {
            User u = new User();
            u.setEmail("attendee@example.com");
            u.setFullName("Default Attendee");
            u.setPassword(passwordEncoder.encode("attendee123"));
            u.setRoles(Set.of(attendeeRole));
            userRepository.save(u);
            LOG.info("Created default attendee: attendee@example.com / attendee123");
        } else {
            LOG.info("Default attendee already present");
        }
    }
}
