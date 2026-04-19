package com.authapi.core.modules.auth.application.support;

import java.time.Duration;

import org.springframework.stereotype.Service;

@Service
public class MinimumResponseTimeService {

    public void run(Duration minimumDuration, Runnable action) {
        long startedAt = System.nanoTime();
        try {
            action.run();
        } finally {
            sleepRemaining(minimumDuration, startedAt);
        }
    }

    private void sleepRemaining(Duration minimumDuration, long startedAt) {
        if (minimumDuration == null || minimumDuration.isZero() || minimumDuration.isNegative()) {
            return;
        }

        long elapsedNanos = System.nanoTime() - startedAt;
        long remainingNanos = minimumDuration.toNanos() - elapsedNanos;
        if (remainingNanos <= 0) {
            return;
        }

        long millis = remainingNanos / 1_000_000L;
        int nanos = (int) (remainingNanos % 1_000_000L);
        try {
            Thread.sleep(millis, nanos);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
    }
}
