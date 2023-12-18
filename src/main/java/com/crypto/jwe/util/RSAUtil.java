package com.crypto.jwe.util;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.FileReader;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class RSAUtil {

    private RSAUtil(){}

    public static RSAPublicKey readPublicKeyFromFile(String path) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");

        try (FileReader keyReader = new FileReader(path); PemReader pemReader = new PemReader(keyReader)) {
            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();

            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
            return (RSAPublicKey) factory.generatePublic(pubKeySpec);
        }
    }

    public static RSAPublicKey readPublicKey(String key) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");

        byte[] content = Base64.getDecoder().decode(key);

        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);

        return (RSAPublicKey) factory.generatePublic(pubKeySpec);
    }

    public static RSAPrivateKey readPrivateKeyFromFile(String path) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");

        try (FileReader keyReader = new FileReader(path); PemReader pemReader = new PemReader(keyReader)) {
            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();

            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(content);
            return (RSAPrivateKey) factory.generatePrivate(privateKeySpec);
        }
    }

    public static RSAPrivateKey readPrivateKey(String key) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");

        byte[] content = Base64.getDecoder().decode(key);

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(content);

        return (RSAPrivateKey) factory.generatePrivate(privateKeySpec);
    }
}