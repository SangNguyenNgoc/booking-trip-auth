package org.example.authserver.exception;

import org.springframework.http.HttpStatus;

import java.util.List;

public class UserNotFoundException extends AbstractException {

    public UserNotFoundException(String error, List<String> messages) {
        super(error, HttpStatus.NOT_FOUND, messages);
    }
}
