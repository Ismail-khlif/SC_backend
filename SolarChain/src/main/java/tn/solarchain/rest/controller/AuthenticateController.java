package tn.solarchain.rest.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import tn.solarchain.rest.vm.LoginVM;
import jakarta.validation.Valid;
import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.*;
import tn.solarchain.security.SecurityUtils;

import static org.reflections.Reflections.log;

/**
 * Controller to authenticate users.
 */
@RestController
@RequestMapping("/api")
@Tag(name = "Authentication", description = "Operations related to user authentication")
public class AuthenticateController {

    private static final Logger LOG = LoggerFactory.getLogger(AuthenticateController.class);

    private final JwtEncoder jwtEncoder;
    private final AuthenticationManager authenticationManager;


    @Value("${jwt.token-validity-in-seconds:0}")

    private long tokenValidityInSeconds;

    @Value("${jwt.token.validity.in.seconds.for.remember.me:0}")
    private long tokenValidityInSecondsForRememberMe;

    public AuthenticateController(JwtEncoder jwtEncoder, AuthenticationManager authenticationManager) {
        this.jwtEncoder = jwtEncoder;
        this.authenticationManager = authenticationManager;
    }

    @Operation(summary = "Authenticate user", description = "Authenticates the user and returns a JWT token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User authenticated successfully"),
            @ApiResponse(responseCode = "401", description = "Invalid login credentials")
    })
    @PostMapping("/authenticate")
    public ResponseEntity<JWTToken> authorize(@Valid @RequestBody LoginVM loginVM) {
        try {
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(loginVM.getUsername(), loginVM.getPassword());

            log.info("Attempting authentication for user: {}", loginVM.getUsername());
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            // Check if the authentication is successful
            if (authentication.isAuthenticated()) {
                log.info("Authentication successful for user: {}", authentication.getName());
            } else {
                log.warn("Authentication failed for user: {}", loginVM.getUsername());
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = this.createToken(authentication, loginVM.isRememberMe());
            log.info("JWT Token created for user: {}", loginVM.getUsername());

            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.setBearerAuth(jwt);
            return new ResponseEntity<>(new JWTToken(jwt), httpHeaders, HttpStatus.OK);

        } catch (Exception e) {
            log.error("Authentication error: ", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }





    @Operation(summary = "Check if the user is authenticated", description = "Returns the authenticated user's login if they are authenticated")
    @ApiResponse(responseCode = "200", description = "User is authenticated")
    @GetMapping(value = "/authenticate", produces = MediaType.TEXT_PLAIN_VALUE)
    public String isAuthenticated(Principal principal) {
        LOG.debug("REST request to check if the current user is authenticated");
        return principal == null ? null : principal.getName();
    }

    public String createToken(Authentication authentication, boolean rememberMe) {
        try {
            // Log the received authentication details
            log.info("Creating token for user: {}", authentication.getName());
            log.info("Authorities for token: {}", authentication.getAuthorities());

            // Extract authorities and log them
            String authorities = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(" "));
            log.info("Authorities to be included in the token: {}", authorities);

            // Set the token issue and expiration times
            Instant now = Instant.now();
            Instant validity;
            if (rememberMe) {
                log.info("Remember me selected, using longer token validity: {} seconds", this.tokenValidityInSecondsForRememberMe);
                validity = now.plus(this.tokenValidityInSecondsForRememberMe, ChronoUnit.SECONDS);
                log.info(String.valueOf(validity));
            } else {
                log.info("Regular token validity: {} seconds", this.tokenValidityInSeconds);
                validity = now.plus(this.tokenValidityInSeconds, ChronoUnit.SECONDS);
                log.info(String.valueOf(validity));
            }

            // Add a small buffer (e.g., 1 second) to ensure the expiration is after issuedAt
            validity = validity.plus(1, ChronoUnit.SECONDS);
            log.info("Issued at time: {}", now);
            log.info("Expires at time (with buffer): {}", validity);

            // Build the JWT claims set and log the claims
            JwtClaimsSet claims = JwtClaimsSet.builder()
                    .issuedAt(now)
                    .expiresAt(validity)
                    .subject(authentication.getName())
                    .claim(SecurityUtils.AUTHORITIES_KEY, authorities)
                    .build();
            log.info("JWT Claims: {}", claims);

            // Build the JWT header and log it
            JwsHeader jwsHeader = JwsHeader.with(SecurityUtils.JWT_ALGORITHM).build();
            log.info("JWT Header: {}", jwsHeader);

            // Encode the JWT and log the result
            String token = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims)).getTokenValue();
            log.info("JWT successfully created for user: {}", authentication.getName());

            return token;
        } catch (Exception e) {
            // Log any exceptions that occur during the token creation process
            log.error("Error during JWT token creation: ", e);
            throw e;  // Rethrow to ensure proper exception handling
        }
    }




    static class JWTToken {
        private String idToken;

        JWTToken(String idToken) {
            this.idToken = idToken;
        }

        public String getIdToken() {
            return idToken;
        }

        public void setIdToken(String idToken) {
            this.idToken = idToken;
        }
    }
}
