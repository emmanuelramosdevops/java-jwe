package com.crypto.jwe.parser;

import com.crypto.jwe.util.JWTUtil;
import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;

public final class SessionParser {

    private SessionParser() {}

    @SneakyThrows
    public static SessionVO parse(SignedJWT jws, String externalJws) {
        String sessionId = jws.getJWTClaimsSet().getClaim(JWTUtil.SESSION_ID_CLAIM).toString();
        String tokenIssuer = jws.getJWTClaimsSet().getClaim(JWTUtil.TOKEN_ISSUER_CLAIM).toString();

        return SessionVO.builder()
            .sessionId(sessionId)
            .tokenIssuer(tokenIssuer)
            .externalJws(externalJws)
            .build();
    }
}