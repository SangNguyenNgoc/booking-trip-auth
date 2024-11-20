package org.example.authserver.services;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Set;
import java.util.function.Supplier;

@Service
@RequiredArgsConstructor
@Log4j2
public class RedisService<T> {

    private final StringRedisTemplate stringRedisTemplate;

    private final ObjectMapper objectMapper;

    public void deleteKeysWithPrefix(String prefix) {
        Set<String> keys = stringRedisTemplate.keys(prefix + "*");
        if (keys != null && !keys.isEmpty()) {
            stringRedisTemplate.delete(keys);
            log.info("Delete cache successfully");
        }
    }

    public void setValue(String key, T value) {
        try {
            String json = objectMapper.writeValueAsString(value);
            Object d = new Object();
            stringRedisTemplate.opsForValue().set(key, json);
            log.info("The cache with key %s was successfully stored".formatted(key));
        } catch (Exception e) {
            log.error("Error connecting to Redis: %s".formatted(e.getMessage()));
        }
    }

    public T getValue(String key, TypeReference<T> typeReference) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.registerModule(new JavaTimeModule());
            String json = stringRedisTemplate.opsForValue().get(key);
            if (json == null) {
                return null;
            }
            return objectMapper.readValue(json, typeReference);
        } catch (IOException e) {
            return null;
        }
    }

    public T convertValue(Supplier<T> supplier, TypeReference<T> typeReference) {
        Object data = supplier.get();
        return objectMapper.convertValue(data, typeReference);
    }
}
