package io.github.pierrecarre.demo.oauth2server.configuration.security;

import org.springframework.stereotype.Component;

//@Component
public class JwtAccessTokenConverter extends org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter {

    public JwtAccessTokenConverter() {
        super();
    }
}
