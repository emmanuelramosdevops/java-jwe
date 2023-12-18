package com.crypto.jwe.exception;

import com.crypto.jwe.web.model.Error;
import com.nimbusds.jose.JOSEException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.text.ParseException;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ParseException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Error parseException(ParseException ex) {
        log.error("Error:", ex);
        return new Error("Error extracting JWT claim");
    }

    @ExceptionHandler(JOSEException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Error joseException(JOSEException ex) {
        log.error("Error:", ex);
        return new Error("Error parsing JWT token");
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Error genericException(Exception ex) {
       log.error("Error:", ex);
       return new Error("Internal server error");
    }
}