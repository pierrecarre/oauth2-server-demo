package io.github.pierrecarre.demo.oauth2server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

@SpringBootApplication
public class Oauth2ServerDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(Oauth2ServerDemoApplication.class, args);
    }

}
