package com.crypto.jwe.util;

import com.crypto.jwe.parser.SessionVO;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
@Component
public final class JWTUtil {

    public static final String JWS_CLAIM = "jws";
    public static final String SESSION_ID_CLAIM = "session_id";
    public static final String TOKEN_ISSUER_CLAIM = "iss";

    private final RSAEncrypter rsaEncrypter;

    private final RSADecrypter rsaDecrypter;

    private final RSASSAVerifier rsaVerifier;

    private final RSASSASigner rsaSigner;

    public String sanitizeJWT(String jwt){
        return StringUtils.remove(jwt, "Bearer").trim();
    }

    @SneakyThrows
    public String generateJWE(String jws){
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_512, EncryptionMethod.A256GCM);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .issuer("jwe")
            .subject("authorization")
            .audience("client_app")
            .expirationTime(DateUtils.addHours(new Date(), 1))

            .notBeforeTime(new Date())
            .issueTime(new Date())
            .jwtID(UUID.randomUUID().toString())

            .claim("jws", jws)

            .build();

        EncryptedJWT jwe = new EncryptedJWT(header, claims);
        jwe.encrypt(rsaEncrypter);

        return jwe.serialize();
    }

    @SneakyThrows
    public String generateJWS(SessionVO sessionVO){
        JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.RS512);

        JWTClaimsSet jwsPayload = new JWTClaimsSet.Builder()
            .issuer("jwe")
            .subject("authorization")
            .audience("client_app")
            .expirationTime(DateUtils.addHours(new Date(), 1))

            .notBeforeTime(new Date())
            .issueTime(new Date())
            .jwtID(UUID.randomUUID().toString())

            .claim("session_id", sessionVO.getSessionId())

            .build();

        SignedJWT signedJWT = new SignedJWT(jwsHeader, jwsPayload);
        signedJWT.sign(rsaSigner);

        return signedJWT.serialize();
    }

    @SneakyThrows
    public EncryptedJWT parseJWE(String jweStr) {
        EncryptedJWT jwe = EncryptedJWT.parse(this.sanitizeJWT(jweStr));
        jwe.decrypt(rsaDecrypter);
        this.showJweInfo(jwe);
        return jwe;
    }

    @SneakyThrows
    public SignedJWT parseJWS(String jwsStr){
        SignedJWT jws = SignedJWT.parse(jwsStr);
        jws.verify(rsaVerifier);
        this.showJwsInfo(jws);
        return jws;
    }

    @SneakyThrows
    private void showHeaderInfo(JWT jwe)  {
        log.info("Issuer:            {}", jwe.getJWTClaimsSet().getIssuer());
        log.info("Subject:           {}", jwe.getJWTClaimsSet().getSubject());
        log.info("Audience:          {}", jwe.getJWTClaimsSet().getAudience());
        log.info("ExpirationTime:    {}", jwe.getJWTClaimsSet().getExpirationTime());

        log.info("NotBeforeTime:     {}", jwe.getJWTClaimsSet().getNotBeforeTime());
        log.info("IssuedAt:          {}", jwe.getJWTClaimsSet().getIssueTime());
        log.info("JWTID:             {}", jwe.getJWTClaimsSet().getJWTID());
    }

    @SneakyThrows
    public void showJweInfo(EncryptedJWT jwe) {
        log.info("=== JWE Info ===");
        showHeaderInfo(jwe);
        log.info("JWS:               {}", jwe.getJWTClaimsSet().getClaim("jws"));
    }

    @SneakyThrows
    public void showJwsInfo(SignedJWT jws)  {
        log.info("=== JWS Info ===");
        showHeaderInfo(jws);
        log.info("SessionId:         {}", jws.getJWTClaimsSet().getClaim("session_id"));
    }
}