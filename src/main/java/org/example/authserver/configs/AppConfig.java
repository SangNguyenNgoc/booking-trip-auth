package org.example.authserver.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.support.converter.JsonMessageConverter;

@Configuration
public class AppConfig {
    @Bean
    public JsonMessageConverter converter() {
        return new JsonMessageConverter();
    }
}
