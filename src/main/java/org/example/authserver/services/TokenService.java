package org.example.authserver.services;

import lombok.RequiredArgsConstructor;
import org.example.authserver.entities.User;
import org.example.authserver.exception.UnauthorizedException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.stereotype.Service;
import org.springframework.security.oauth2.jwt.*;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final StringRedisTemplate redisTemplate;

    private final JwtEncoder jwtEncoder;

    private final JwtDecoder jwtDecoder;

    public void blacklistToken(String token) {
        // Lưu access token vào Redis với thời gian hết hạn
        redisTemplate.opsForValue().set(token, "blacklisted");
    }

    public boolean isTokenBlacklisted(String token) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(token));
    }

    public String generateVerifyToken(User user) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plus(15, ChronoUnit.MINUTES))
                .subject(user.getUsername())
                .claim("scope", List.of("VERIFY"))
                .notBefore(Instant.ofEpochSecond(now.getEpochSecond() + 60))
                .build();
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    public boolean isTokenExpired(String token) {
        try {
            Jwt decodedJwt = jwtDecoder.decode(token);
            Instant expiresAt = decodedJwt.getExpiresAt();
            assert expiresAt != null;
            return expiresAt.isBefore(Instant.now());
        } catch (JwtException e) {
            return true;
        }
    }

    public String extractSubject(String token) {
        Jwt jwt = jwtDecoder.decode(token);
        return jwt.getSubject();
    }

    public String extractClaim(String claim, String token) {
        Jwt jwt = jwtDecoder.decode(token);
        return jwt.getClaim(claim);
    }

    public String validateTokenBearer(String token) {
        if (token == null || !token.startsWith("Bearer ")) {
            throw new UnauthorizedException("Unauthorized", List.of("Unauthorized"));
        } else {
            token = token.substring(7);
            return token;
        }
    }

    public String getRandomNumber(int length) {
        SecureRandom random = new SecureRandom();
        StringBuilder uid = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            int digit = random.nextInt(10);
            uid.append(digit);
        }
        return uid.toString();
    }
}
