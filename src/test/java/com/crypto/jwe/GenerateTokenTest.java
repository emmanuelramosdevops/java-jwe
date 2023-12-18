package com.crypto.jwe;

import com.crypto.jwe.util.RSAUtil;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.time.DateUtils;
import org.junit.jupiter.api.Test;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;

public class GenerateTokenTest {

    @Test
    public void generateNestedToken() throws Exception {
       String jws = generateJWS();
       System.out.println("Token Verified: " + verifyJWS(jws));
       System.out.println("JWS: " + jws);

       String jwe = generateJWE(jws);
       System.out.println("JWE: " + jwe);

       readJWE(jwe);
    }

    private String generateJWS() throws Exception {
        RSAPrivateKey privateKey = RSAUtil.readPrivateKeyFromFile("./crypto/external_private_key.pem");

        JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.RS256);

        JWTClaimsSet jwsPayload = new JWTClaimsSet.Builder()
            .issuer("external")
            .subject("authorization")
            .audience("api")
            .expirationTime(DateUtils.addHours(new Date(), 1))

            .notBeforeTime(new Date())
            .issueTime(new Date())
            .jwtID(UUID.randomUUID().toString())

            .claim("session_id", "2341-85643-7632-1753")

            .build();

        JWSSigner signer = new RSASSASigner(privateKey);

        SignedJWT signedJWT = new SignedJWT(jwsHeader, jwsPayload);
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    private boolean verifyJWS(String jwsStr) throws Exception {
        RSAPublicKey publicKey = RSAUtil.readPublicKeyFromFile("./crypto/external_public_key.pem");

        JWSVerifier verifier = new RSASSAVerifier(publicKey);

        SignedJWT jws = SignedJWT.parse(jwsStr);

        return jws.verify(verifier);
    }

    private String generateJWE(String jws) throws Exception {

        RSAPublicKey publicKey = RSAUtil.readPublicKeyFromFile("./crypto/internal_public_key.pem");
        RSAEncrypter encrypter = new RSAEncrypter(publicKey);

        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .issuer("oam")
            .subject("header_enrichment_authorization")
            .audience("header_enrichment_router")
            .expirationTime(DateUtils.addHours(new Date(), 1))

            .notBeforeTime(new Date())
            .issueTime(new Date())
            .jwtID(UUID.randomUUID().toString())

            .claim("jws", jws)

            .build();

        EncryptedJWT jwe = new EncryptedJWT(header, claims);
        jwe.encrypt(encrypter);

        return jwe.serialize();
    }

    private void readJWE(String jweStr) throws Exception {
        RSAPrivateKey privateKey = RSAUtil.readPrivateKeyFromFile("./crypto/internal_private_key.pem");

        RSADecrypter decrypter = new RSADecrypter(privateKey);

        EncryptedJWT jwe = EncryptedJWT.parse(jweStr);
        jwe.decrypt(decrypter);

        System.out.println("Issuer: [" + jwe.getJWTClaimsSet().getIssuer() + "]");
        System.out.println("Subject: [" + jwe.getJWTClaimsSet().getSubject() + "]");
        System.out.println("Audience: [" + jwe.getJWTClaimsSet().getAudience() + "]");
        System.out.println("Expiration Time: [" + jwe.getJWTClaimsSet().getExpirationTime() + "]");

        System.out.println("Not Before Time: [" + jwe.getJWTClaimsSet().getNotBeforeTime() + "]");
        System.out.println("Issued At: [" + jwe.getJWTClaimsSet().getIssueTime() + "]");
        System.out.println("JWT ID: [" + jwe.getJWTClaimsSet().getJWTID() + "]");

        System.out.println("JWS: [" + jwe.getJWTClaimsSet().getClaim("jws") + "]");
    }
}