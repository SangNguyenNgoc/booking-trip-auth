package org.example.authserver.exception;

import org.springframework.http.HttpStatus;

import java.util.List;

public class RoleNotFoundException extends AbstractException {
    public RoleNotFoundException(String error, List<String> messages) {
        super(error, HttpStatus.INTERNAL_SERVER_ERROR, messages);
    }
}
