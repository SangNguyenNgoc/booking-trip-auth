package org.example.authserver.dtos;

import lombok.Builder;
import lombok.Data;

import java.io.Serializable;

@Data
@Builder
public class AccountCreatedError implements Serializable {
    private String message;
    private String profileId;
    private String email;
}
