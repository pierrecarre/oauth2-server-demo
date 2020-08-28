package io.github.pierrecarre.demo.oauth2server.configuration.security;

import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.stereotype.Component;

//@Component
public class TokenStore extends JwtTokenStore {

    public TokenStore(final JwtAccessTokenConverter jwtTokenEnhancer) {
        super(jwtTokenEnhancer);
    }
}
