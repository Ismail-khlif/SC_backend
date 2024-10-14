package tn.solarchain.security;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import tn.solarchain.security.jwt.TokenProvider;

@Component
public class TestAuthenticationManager implements CommandLineRunner {
    private final AuthenticationManager authenticationManager;
    private static final Logger log = LoggerFactory.getLogger(TokenProvider.class);



    public TestAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public void run(String... args) throws Exception {
        try {
            String username = "admin";
            String rawPassword = "admin123"; // Plain-text password to test

           // log.info("Testing authentication for user: {}", username);
            //log.info("Raw password: {}", rawPassword);

            // Create the authentication token with raw password
            Authentication authenticationToken =
                    new UsernamePasswordAuthenticationToken(username, rawPassword);


            log.info("Authentication successful for user: {}", authenticationToken.getName());

        } catch (Exception e) {
            log.error("Authentication failed: {}", e.getMessage(), e);
        }
    }
}
