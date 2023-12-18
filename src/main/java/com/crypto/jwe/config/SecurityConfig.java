package com.crypto.jwe.config;

import com.crypto.jwe.util.RSAUtil;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import io.micrometer.common.util.StringUtils;
import lombok.Getter;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Getter
@Configuration
public class SecurityConfig implements InitializingBean {

    @Value("${INTERNAL_PRIVATE_KEY}")
    private String internalPrivateKey;

    @Value("${EXTERNAL_PUBLIC_KEY}")
    private String externalPublicKey;

    public void afterPropertiesSet() {
        if (StringUtils.isEmpty(internalPrivateKey))
            throw new IllegalArgumentException("Environment variable INTERNAL_PRIVATE_KEY must be configured");

        if (StringUtils.isEmpty(externalPublicKey))
            throw new IllegalArgumentException("Environment variable EXTERNAL_PUBLIC_KEY must be configured");
    }

    @Bean
    public RSADecrypter rsaDecrypter() throws Exception {
        RSAPrivateKey privateKey = RSAUtil.readPrivateKey(this.internalPrivateKey);
        return new RSADecrypter(privateKey);
    }

    @Bean
    public RSAEncrypter rsaEncrypter() throws Exception {
        RSAPublicKey publicKey = RSAUtil.readPublicKey(this.externalPublicKey);
        return new RSAEncrypter(publicKey);
    }

    @Bean
    public RSASSAVerifier rsaVerifier() throws Exception {
        RSAPublicKey publicKey = RSAUtil.readPublicKey(this.externalPublicKey);
        return new RSASSAVerifier(publicKey);
    }

    @Bean
    public RSASSASigner rsaSigner() throws Exception {
        RSAPrivateKey privateKey = RSAUtil.readPrivateKey(this.internalPrivateKey);
        return new RSASSASigner(privateKey);
    }
}