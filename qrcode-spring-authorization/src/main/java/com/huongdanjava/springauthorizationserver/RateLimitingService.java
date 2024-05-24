package com.huongdanjava.springauthorizationserver;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bucket4j;
import io.github.bucket4j.Refill;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class RateLimitingService {
    private final ConcurrentHashMap<String, Bucket> bucketCache = new ConcurrentHashMap<String, Bucket>();

    public Bucket resolveBucket(String ipAddress) {
        return bucketCache.computeIfAbsent(ipAddress, this::newBucket);
    }

    public void deleteIfExists(String ipAddress) {
        bucketCache.remove(ipAddress);
    }

    // limit rate: 3 times every minute
    private Bucket newBucket(String ipAddress) {
        final Integer limitPerMinute = 5;
        return Bucket4j.builder()
                .addLimit(Bandwidth.classic(limitPerMinute, Refill.intervally(limitPerMinute, Duration.ofMinutes(1))))
                .build();
    }
}
