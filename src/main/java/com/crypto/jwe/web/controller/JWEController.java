package com.crypto.jwe.web.controller;

import com.crypto.jwe.service.JWEService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping("api/jwe")
public class JWEController {

    private final JWEService jweService;

    @GetMapping
    public String readToken(@RequestHeader(name = "Authorization") String authToken){
            return jweService.readToken(authToken);
    }
}