package com.secureuserapi.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;

/**
 * Enables Spring's async processing and defines the thread pool used by @Async methods.
 *
 * Without this, @Async uses Spring's default executor — a SimpleAsyncTaskExecutor
 * that creates a NEW thread for every single task. That's the same problem as
 * new Thread(...) — unbounded thread creation under load.
 *
 * By defining our own ThreadPoolTaskExecutor we control:
 * - corePoolSize:  threads always kept alive (even when idle)
 * - maxPoolSize:   hard ceiling on threads under heavy load
 * - queueCapacity: tasks that wait when all threads are busy
 * - threadNamePrefix: makes async threads identifiable in logs/profilers
 */
@Configuration
@EnableAsync
public class AsyncConfig {

    @Bean(name = "taskExecutor")
    public Executor taskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(3);         // 3 threads always ready
        executor.setMaxPoolSize(10);         // burst up to 10 under load
        executor.setQueueCapacity(100);      // queue up to 100 tasks before rejecting
        executor.setThreadNamePrefix("async-"); // logs will show "async-1", "async-2"
        executor.initialize();
        return executor;
    }
}
