package org.example.authserver.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.*;
import org.example.authserver.entities.User;

import java.io.Serializable;

/**
 * DTO for {@link User}
 */
@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class AccountCreateRequest implements Serializable {
    @NotBlank(message = "profile Id must not be blank")
    private String profileId;
    @Email(message = "User name invalid")
    private String username;
    @Pattern(message = "Password invalid", regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*[\\W_]).{8,}$ ")
    @NotBlank(message = "password must not be blank")
    private String password;
}