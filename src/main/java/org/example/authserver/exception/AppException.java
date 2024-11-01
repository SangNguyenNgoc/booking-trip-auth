package org.example.authserver.exception;

import org.springframework.http.HttpStatus;

import java.util.List;

public class AppException extends AbstractException {

    public AppException(String error, HttpStatus status, List<String> messages) {
        super(error, status, messages);
    }
}
