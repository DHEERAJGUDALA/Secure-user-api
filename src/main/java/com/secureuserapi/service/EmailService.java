package com.secureuserapi.service;

import com.secureuserapi.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/**
 * Handles all email operations asynchronously.
 *
 * Every public method is @Async — they run on the "taskExecutor" thread pool
 * defined in AsyncConfig, NOT on the HTTP request thread.
 *
 * In production you'd inject JavaMailSender here and send real emails.
 * For now we simulate with a Thread.sleep() + log — so you can actually
 * SEE the async behavior: the HTTP response returns instantly while
 * the log appears 2 seconds later on thread "async-1".
 */
@Service
public class EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailService.class);

    @Async("taskExecutor")
    public void sendWelcomeEmail(User user) {
        try {
            // Simulates a real SMTP call taking 2 seconds
            Thread.sleep(2000);
            log.info("[{}] Welcome email sent to: {}",
                    Thread.currentThread().getName(),
                    user.getUsername());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Email sending interrupted for: {}", user.getUsername());
        }
    }
}
