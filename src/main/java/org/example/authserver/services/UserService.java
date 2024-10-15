package org.example.authserver.services;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.example.authserver.dtos.AccountCreateRequest;
import org.example.authserver.interfaces.RoleRepository;
import org.example.authserver.interfaces.UserMapper;
import org.example.authserver.interfaces.UserRepository;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

public interface UserService {
    void createAccount(AccountCreateRequest accountCreateRequest);
}
@Service
@RequiredArgsConstructor
@Log4j2
class UserServiceImpl implements UserService{

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    @Override
    @Transactional
    @KafkaListener(
            topics = "createAccount",
            id = "createAccountGroup"
    )
    public void createAccount(AccountCreateRequest accountCreateRequest) {
        log.info("Received account" + accountCreateRequest.getProfileId());
        var role = roleRepository.findById(2).orElseThrow();
        var newAccountUser = userMapper.toEntity(accountCreateRequest);
        newAccountUser.setPassword(passwordEncoder.encode(newAccountUser.getPassword()));
        newAccountUser.setRole(role);
        newAccountUser.setVerify(false);
        userRepository.save(newAccountUser);
    }
}

