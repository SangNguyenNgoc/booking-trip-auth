package org.example.authserver.interfaces;

import org.example.authserver.entities.Provider;
import org.example.authserver.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, String> {

    @Query("select u from User u where u.username = ?1")
    Optional<User> findByUsername(String email);

    Optional<User>findByProfileIdAndVerifyFalse(String userId);

    Optional<User> findByUsernameAndProvider(String username, Provider provider);

    @Transactional
    @Modifying
    @Query("update User u set u.provider = ?1 where u.id = ?2")
    int updateProviderById(Provider provider, String id);
}
