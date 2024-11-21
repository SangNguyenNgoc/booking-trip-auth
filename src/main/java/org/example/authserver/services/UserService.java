package org.example.authserver.services;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.example.authserver.dtos.*;
import org.example.authserver.entities.CustomOAuth2User;
import org.example.authserver.entities.Provider;
import org.example.authserver.entities.User;
import org.example.authserver.exception.AppException;
import org.example.authserver.exception.TokenExpiredException;
import org.example.authserver.exception.UserNotFoundException;
import org.example.authserver.interfaces.RoleRepository;
import org.example.authserver.interfaces.UserMapper;
import org.example.authserver.interfaces.UserRepository;
import org.springframework.beans.factory.annotation.Value;
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
    String requireForgotPassword(String email);
    ForgotPassword verifyForgotPassword(String token);
    String forgotPassword(FormForgotPassword forgotPassword);
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
    private final RedisService<AccountNotified> redisTemplate;

    @Value("${url.home-page-url")
    private String homeUri;
    @Value("${url.forgot-password-url}")
    private String forgotPasswordUri;

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
                    .verifyToken(tokenService.generateVerifyToken(user, List.of("VERIFY")))
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
        var scopes = tokenService.extractScope(token);
        if(!scopes.contains("VERIFY") || scopes.size() != 1){
            throw new TokenExpiredException("Scope invalid", List.of("Scope invalid"));
        }
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
        String name = oAuth2User.getAttribute("name");
        var user = userRepository.findByUsername(email);
        if (user.isPresent()) {
            return new CustomOAuth2User(user.get().getAuthorities(),
                    oAuth2User.getAttributes(), user.get());
        } else {
            var role = roleRepository.findById(2).orElseThrow(
                    ()-> new AppException("Role not found", HttpStatus.NOT_FOUND, List.of("Role not found"))
            );
            var password = UUID.randomUUID().toString();
            var profileId = UUID.randomUUID().toString();
            User newUser = User.builder()
                    .profileId(profileId)
                    .username(email)
                    .password(passwordEncoder.encode(password))
                    .provider(Provider.GOOGLE)
                    .role(role)
                    .verify(true)
                    .build();
            userRepository.save(newUser);
            var accountNotified = AccountNotified.builder()
                    .email(email)
                    .password(password)
                    .profileId(profileId)
                    .fullName(name)
                    .build();
            kafkaTemplate.send("AccountCreatedGG", accountNotified);
            kafkaTemplate.send("AccountCreatedGGNotified", accountNotified);
            redisTemplate.setValue(profileId, accountNotified);
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

    @Override
    public String requireForgotPassword(String email){
        var user = userRepository.findByUsername(email)
                .orElseThrow(() -> new UserNotFoundException("Not found", List.of("Not found user with email" + email)));
        var forgotPassword = ForgotPassword.builder()
                .email(email)
                .profileId(user.getProfileId())
                .verify(forgotPasswordUri + "?t=" + tokenService.generateVerifyToken(user,List.of("REQUIRE_FORGOT_PASSWORD")))
                .build();
        kafkaTemplate.send("ForgotPassword", forgotPassword);
        return "success";
    }

    public ForgotPassword verifyForgotPassword(String token){
        if (tokenService.isTokenExpired(token)) {
            throw new TokenExpiredException("Url has expired.", List.of("Token has expired"));
        }
        String userName = tokenService.extractSubject(token);
        var scopes = tokenService.extractScope(token);
        if(!scopes.contains("REQUIRE_FORGOT_PASSWORD") || scopes.size() != 1){
            throw new TokenExpiredException("Scope invalid", List.of("Scope invalid"));
        }
        var user = userRepository.findByProfileId(userName)
                .orElseThrow(() -> new UserNotFoundException("NOT FOUND", List.of("User not found")));
        return ForgotPassword.builder()
                .email(user.getEmail())
                .profileId(user.getProfileId())
                .verify(tokenService.generateVerifyToken(user,List.of("FORGOT_PASSWORD")))
                .build();
    }

    @Transactional
    public String forgotPassword(FormForgotPassword forgotPassword){
        if (tokenService.isTokenExpired(forgotPassword.getVerify())) {
            throw new TokenExpiredException("Url has expired.", List.of("Token has expired"));
        }
        String userName = tokenService.extractSubject(forgotPassword.getVerify());
        var scopes = tokenService.extractScope(forgotPassword.getVerify());
        if(!scopes.contains("FORGOT_PASSWORD") || scopes.size() != 1){
            throw new TokenExpiredException("Scope invalid", List.of("Scope invalid"));
        }
        var user = userRepository.findByProfileId(userName)
                .orElseThrow(() -> new UserNotFoundException("NOT FOUND", List.of("User not found")));
        user.setPassword(passwordEncoder.encode(forgotPassword.getPassword()));
        return homeUri;
    }


}

