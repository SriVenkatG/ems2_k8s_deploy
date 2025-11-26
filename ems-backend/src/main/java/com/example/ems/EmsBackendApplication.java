// src/main/java/com/example/ems/EmsBackendApplication.java
package com.example.ems;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableAsync
@EnableScheduling   // ✅ Enable scheduling for reminders
public class EmsBackendApplication {
    public static void main(String[] args) {
        SpringApplication.run(EmsBackendApplication.class, args);
    }
}
