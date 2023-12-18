package com.crypto.jwe.service;

import com.crypto.jwe.parser.SessionParser;
import com.crypto.jwe.parser.SessionVO;
import com.crypto.jwe.util.JWTUtil;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@RequiredArgsConstructor
@Service
public class JWEService {

    private final JWTUtil jwtUtil;

    @SneakyThrows
    public String readToken(String externalJwe){

        SessionVO mobileSessionVO = parseExternalJwe(externalJwe);

        return generateInternalJwe(mobileSessionVO);
    }

    @SneakyThrows
    private SessionVO parseExternalJwe(String externalJwe){

        /* External Flow */
        log.info("Parsing external JWE token: [{}]", externalJwe);
        EncryptedJWT jwe = jwtUtil.parseJWE(externalJwe);

        log.info("Parsing external JWS token");
        String externalJws = jwe.getJWTClaimsSet().getClaim(JWTUtil.JWS_CLAIM).toString();
        SignedJWT jws = jwtUtil.parseJWS(externalJws);

        return SessionParser.parse(jws, externalJws);
    }

    private String generateInternalJwe(SessionVO sessionVO){

        /* Internal Flow */
        log.info("Generating internal JWS");
        String internalJws = jwtUtil.generateJWS(sessionVO);
        log.info(internalJws);

        log.info("Generating internal JWE");
        String internalJwe = jwtUtil.generateJWE(internalJws);
        log.info(internalJwe);

        return internalJwe;
    }
}