package io.github.pierrecarre.demo.oauth2server.configuration.security;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class PasswordEncoder implements org.springframework.security.crypto.password.PasswordEncoder {

    private static final String BCRYPT = "bcrypt";

    private DelegatingPasswordEncoder delegatingPasswordEncoder;

    public PasswordEncoder() {
        this.delegatingPasswordEncoder = new DelegatingPasswordEncoder(
                BCRYPT,
                Map.of(BCRYPT, new BCryptPasswordEncoder(4))
        );
    }

    @Override
    public boolean upgradeEncoding(String encodedPassword) {
        return this.delegatingPasswordEncoder.upgradeEncoding(encodedPassword);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return this.delegatingPasswordEncoder.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return this.delegatingPasswordEncoder.matches(rawPassword, encodedPassword);
    }
}
