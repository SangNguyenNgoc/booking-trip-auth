package org.example.authserver.services;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.example.authserver.dtos.AccountCreateRequest;
import org.example.authserver.dtos.AccountCreatedError;
import org.example.authserver.dtos.AccountVerified;
import org.example.authserver.entities.CustomOAuth2User;
import org.example.authserver.entities.Provider;
import org.example.authserver.entities.User;
import org.example.authserver.exception.AppException;
import org.example.authserver.exception.TokenExpiredException;
import org.example.authserver.exception.UserNotFoundException;
import org.example.authserver.interfaces.RoleRepository;
import org.example.authserver.interfaces.UserMapper;
import org.example.authserver.interfaces.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

public interface UserService {
    void createAccount(AccountCreateRequest accountCreateRequest);
    void verify(String token);
    CustomOAuth2User processOauth2User(OAuth2User oAuth2User);
    void updateProvider(Provider provider, String id);
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

    @Override
    @Transactional
    @KafkaListener(
            topics = "createAccount",
            id = "createAccountGroup"
    )
    public void createAccount(AccountCreateRequest accountCreateRequest) {
        log.info("Received account{}", accountCreateRequest.getFullName());
        try {
            var role = roleRepository.findById(accountCreateRequest.getRoleId()).orElseThrow(
                    ()-> new AppException("Role not found", HttpStatus.NOT_FOUND, List.of("Role not found"))
            );
            var newAccountUser = userMapper.toEntity(accountCreateRequest);
            newAccountUser.setPassword(passwordEncoder.encode(newAccountUser.getPassword()));
            newAccountUser.setRole(role);
            newAccountUser.setVerify(false);
            newAccountUser.setProvider(Provider.LOCAL);
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
    public void verify(String token) {
        if (tokenService.isTokenExpired(token)) {
            throw new TokenExpiredException("Url has expired.", List.of("Token has expired"));
        }
        String userName = tokenService.extractSubject(token);
        User user = userRepository.findByProfileIdAndVerifyFalse(userName)
                .orElseThrow(() -> new UserNotFoundException("User not found", List.of("User not found or already verified.")));
        user.setVerify(true);
//        try {
//            String codeVerified = authorizationCodeService.generateCodeVerifier();
//            String authCode = authorizationCodeService.generateAuthorizationCode(user, codeVerified).getTokenValue();
//            return UriComponentsBuilder.fromUriString(baseFeUri)
//                    .path("/verified") // /redirect to client page to handler, fe will get parameter and call token from be
//                    .queryParam("code", codeVerified)
//                    .queryParam("code_verified", authCode)
//                    .build()
//                    .toUri();
//        } catch (NoSuchAlgorithmException e) {
//            return UriComponentsBuilder.fromUriString(baseFeUri)
//                    .path("/verified")
//                    .queryParam("server-error", true)
//                    .build()
//                    .toUri();
//        }
    }


    @Override
    @Transactional
    public CustomOAuth2User processOauth2User(OAuth2User oAuth2User) {
        String email = oAuth2User.getAttribute("email");
        var user = userRepository.findByUsername(email);
        if (user.isPresent()) {
            return new CustomOAuth2User(user.get().getAuthorities(),
                    oAuth2User.getAttributes(), user.get());
        } else {
            var role = roleRepository.findById(2).orElseThrow(
                    ()-> new AppException("Role not found", HttpStatus.NOT_FOUND, List.of("Role not found"))
            );
            User newUser = User.builder()
                    .profileId(UUID.randomUUID().toString())
                    .username(email)
                    .password(passwordEncoder.encode(UUID.randomUUID().toString()))
                    .provider(Provider.GOOGLE)
                    .role(role)
                    .verify(true)
                    .build();
            userRepository.save(newUser);
            return CustomOAuth2User.builder()
                    .user(newUser)
                    .attributes(oAuth2User.getAttributes())
                    .authorities(newUser.getAuthorities())
                    .build();
        }
    }

    @Override
    @Transactional
    public void updateProvider(Provider provider, String id) {
        var user = userRepository.findById(id).orElseThrow(
                ()-> new AppException("User not found", HttpStatus.NOT_FOUND, List.of("User not found"))
        );
        user.setProvider(provider);
        user.setVerify(true);
    }
}

