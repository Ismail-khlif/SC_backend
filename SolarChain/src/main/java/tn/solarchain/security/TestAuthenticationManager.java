package tn.solarchain.security;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import static org.reflections.Reflections.log;

@Component
public class TestAuthenticationManager implements CommandLineRunner {

    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    public TestAuthenticationManager(AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        try {
            String username = "admin";
            String rawPassword = "admin"; // Change this to the plain-text password you want to test

            log.info("Testing authentication for user: {}", username);
            log.info("Raw password: {}", rawPassword);

            // Create the authentication token
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(username, rawPassword);
            log.info(String.valueOf(authenticationToken));
            // Try authenticating
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            log.info("Authentication successful for user: {}", authentication.getName());

        } catch (BadCredentialsException e) {
            log.error("Bad credentials: Incorrect username or password.");
        } catch (Exception e) {
            log.error("Authentication failed due to an exception: ", e);
        }
    }

}
