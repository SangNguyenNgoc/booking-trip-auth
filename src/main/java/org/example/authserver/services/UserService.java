package org.example.authserver.services;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.example.authserver.dtos.AccountCreateRequest;
import org.example.authserver.dtos.AccountCreatedError;
import org.example.authserver.dtos.AccountVerified;
import org.example.authserver.entities.User;
import org.example.authserver.exception.AppException;
import org.example.authserver.interfaces.RoleRepository;
import org.example.authserver.interfaces.UserMapper;
import org.example.authserver.interfaces.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public interface UserService {
    void createAccount(AccountCreateRequest accountCreateRequest);
    public URI verify(String token);
}
@Service
@RequiredArgsConstructor
@Log4j2
class UserServiceImpl implements UserService{

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final KafkaTemplate<String, Object> kafkaTemplate;
    private final TokenService tokenService;
    private final AuthorizationCodeService authorizationCodeService;

    @Value("${url.home-page-url}")
    private String baseFeUri;

    @Override
    @Transactional
    @KafkaListener(
            topics = "createAccount",
            id = "createAccountGroup"
    )
    public void createAccount(AccountCreateRequest accountCreateRequest) {
        log.info("Received account" + accountCreateRequest.getFullName());
        try {
            var role = roleRepository.findById(accountCreateRequest.getRoleId()).orElseThrow(
                    ()-> new AppException("Role not found", HttpStatus.NOT_FOUND, List.of("Role not found"))
            );
            var newAccountUser = userMapper.toEntity(accountCreateRequest);
            newAccountUser.setPassword(passwordEncoder.encode(newAccountUser.getPassword()));
            newAccountUser.setRole(role);
            newAccountUser.setVerify(false);
            var user =userRepository.save(newAccountUser);
            var accountVerified = AccountVerified.builder()
                    .email(accountCreateRequest.getUsername())
                    .fullName(accountCreateRequest.getFullName())
                    .verifyToken(tokenService.generateVerifyToken(user))
                    .build();

            kafkaTemplate.send("VerifyAccount", accountVerified);
        }catch (Exception ex){
            kafkaTemplate.send("AccountCreatedFailed", AccountCreatedError.builder()
                    .email(accountCreateRequest.getUsername())
                    .profileId(accountCreateRequest.getProfileId())
                    .message(ex.getMessage())
            );
        }

    }

    @Override
    @Transactional
    public URI verify(String token) {
        if (tokenService.isTokenExpired(token)) {
            return UriComponentsBuilder.fromUriString(baseFeUri)
                    .path("/") // /redirect to client page to handler, fe will get parameter and call token from be
                    .queryParam("expired_url", true)
                    .build()
                    .toUri();
        }
        String userName = tokenService.extractSubject(token);
        User user = userRepository.findByProfileIdAndVerifyFalse(userName).orElseThrow(
                () -> new UsernameNotFoundException("User not found"));
        user.setVerify(true);
        try {
            String codeVerified = authorizationCodeService.generateCodeVerifier();
            String authCode = authorizationCodeService.generateAuthorizationCode(user, codeVerified).getTokenValue();
            return UriComponentsBuilder.fromUriString(baseFeUri)
                    .path("/") // /redirect to client page to handler, fe will get parameter and call token from be
                    .queryParam("code", codeVerified)
                    .queryParam("code_verified", authCode)
                    .build()
                    .toUri();
        } catch (NoSuchAlgorithmException e) {
            throw new AppException("Server error.", HttpStatus.INTERNAL_SERVER_ERROR, List.of("Internal server error"));
        }
    }
}

