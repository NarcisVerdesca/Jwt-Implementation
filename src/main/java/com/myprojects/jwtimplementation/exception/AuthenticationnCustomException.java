package com.myprojects.jwtimplementation.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;
@Getter
@Setter
@AllArgsConstructor
public class AuthenticationnCustomException extends Throwable {
    private HttpStatus status;
    private String message;
}
