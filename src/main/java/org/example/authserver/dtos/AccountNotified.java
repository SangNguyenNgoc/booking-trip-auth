package org.example.authserver.dtos;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AccountNotified implements Serializable {
    private String profileId;
    private String email;
    private String password;
    private String fullName;
}
