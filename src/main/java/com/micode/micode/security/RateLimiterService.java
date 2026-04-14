package com.micode.micode.security;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Service
public class RateLimiterService {

    private final Map<String, Instant> lastRequest = new HashMap<>();

    public boolean isAllowed(String ip) {
        Instant now = Instant.now();

        if (lastRequest.containsKey(ip)) {
            Instant last = lastRequest.get(ip);

            // --- Une requête toutes les 2 secondes ---
            if (now.minusSeconds(2).isBefore(last)) {
                return false;
            }
        }

        lastRequest.put(ip, now);
        return true;
    }
}
