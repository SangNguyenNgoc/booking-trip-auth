package org.example.authserver.services;

import lombok.RequiredArgsConstructor;
import org.example.authserver.entities.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.time.Instant;
import java.util.*;

@Service
@RequiredArgsConstructor
public class AuthorizationCodeService {
    private final RegisteredClientRepository registeredClientRepository;

    private final OAuth2AuthorizationService authorizationService;

    private final UserDetailsService userDetailsService;

    @Value("${client.client-id[0]:default}")
    private String clientId;

    @Value("${client.redirect-uris[0]:default}")
    private String redirectUri;

    public OAuth2AuthorizationCode generateAuthorizationCode(User user, String codeVerifier) throws NoSuchAlgorithmException {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new IllegalArgumentException("Client not found: " + clientId);
        }
        String codeChallenge = null;
        try {
            codeChallenge = generateCodeChallenge(codeVerifier);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, codeChallenge);
        additionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");

        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .clientId(clientId)
                .authorizationUri("/oauth2/authorize")
                .redirectUri(redirectUri)
                .scopes(Collections.singleton(OidcScopes.OPENID))
                .state(UUID.randomUUID().toString())
                .additionalParameters(additionalParameters)
                .build();

        OAuth2AuthorizationCode authorizationCode = null;
        authorizationCode = new OAuth2AuthorizationCode(
                codeVerifier, Instant.now(), Instant.now().plusSeconds(3000));

        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getEmail());
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(user.getUsername())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .refreshToken(new OAuth2RefreshToken(UUID.randomUUID().toString(), Instant.now(), Instant.now().plusSeconds(300)))
                .attribute(Principal.class.getName(), authenticationToken)
                .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest)
                .token(authorizationCode)
                .build();

        authorizationService.save(authorization);

        return authorizationCode;
    }

    public String generateCodeVerifier() throws NoSuchAlgorithmException {
        String uuid = UUID.randomUUID().toString();
        byte[] bytes = uuid.getBytes(StandardCharsets.US_ASCII);
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] digest = messageDigest.digest(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    public String generateCodeChallenge(String codeVerifier) throws NoSuchAlgorithmException {
        byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] digest = messageDigest.digest(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    public String checkAuth(String authId, String tokenValue) {
        OAuth2Authorization authorization = authorizationService.findById(authId);
        assert authorization != null;
        System.out.println(authorization);
        return authorization.getToken(tokenValue).getToken().getTokenValue();
    }
}
