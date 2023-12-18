package com.crypto.jwe.parser;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class SessionVO {

    private String tokenIssuer;
    private String sessionId;
    private String externalJws;

}