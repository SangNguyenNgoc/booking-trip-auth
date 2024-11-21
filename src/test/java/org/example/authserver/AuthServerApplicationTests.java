package org.example.authserver;

import org.example.authserver.entities.Provider;
import org.example.authserver.entities.User;
import org.example.authserver.services.TokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

@SpringBootTest
class AuthServerApplicationTests {
    @Autowired
    TokenService tokenService;

    @Test
    void contextLoads() {
        var user = User.builder()
                .id("abc")
                .username("abc")
                .profileId("abc")
                .build();
        var token = tokenService.generateVerifyToken(user, List.of("VERIFY"));
        System.out.println(token);
//        var list = (List<String>) tokenService.extractClaim("scope", token);
//        list.forEach(System.out::println);
    }

}
