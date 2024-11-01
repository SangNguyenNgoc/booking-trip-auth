package org.example.authserver.exception;

import org.springframework.http.HttpStatus;

import java.util.List;

public class UnauthorizedException extends AbstractException{
    public UnauthorizedException(String error, List<String> messages) {
        super(error, HttpStatus.UNAUTHORIZED, messages);
    }
}
