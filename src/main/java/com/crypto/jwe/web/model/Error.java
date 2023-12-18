package com.crypto.jwe.web.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Error {

    private String message;

    public Error(String message) {
        this.setMessage(message);
    }
}