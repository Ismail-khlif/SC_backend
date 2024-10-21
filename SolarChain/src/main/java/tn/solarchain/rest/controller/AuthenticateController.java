package tn.solarchain.rest.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.*;
import tn.solarchain.domain.RefreshToken;
import tn.solarchain.domain.User;
import tn.solarchain.rest.vm.LoginVM;
import jakarta.validation.Valid;
import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.Set;
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
import org.springframework.web.bind.annotation.*;
import tn.solarchain.rest.vm.RefreshTokenVM;
import tn.solarchain.security.SecurityUtils;
import tn.solarchain.service.RefreshTokenService;
import tn.solarchain.service.UserService;
import tn.solarchain.service.dto.JWTToken;

import static org.reflections.Reflections.log;

/**
 * Controller to authenticate users.
 */
@Slf4j
@RestController
@RequestMapping("/api")
@Tag(name = "Authentication", description = "Operations related to user authentication")
public class AuthenticateController {

    private static final Logger LOG = LoggerFactory.getLogger(AuthenticateController.class);

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;
    private final UserService userService;
    @Value("${jwt.token-validity-in-seconds:0}")

    private long tokenValidityInSeconds;

    @Value("${jwt.token.validity.in.seconds.for.remember.me:0}")
    private long tokenValidityInSecondsForRememberMe;

    public AuthenticateController(JwtDecoder jwtDecoder,JwtEncoder jwtEncoder, AuthenticationManager authenticationManager, RefreshTokenService refreshTokenService,UserService userService) {
        this.jwtEncoder = jwtEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtDecoder=jwtDecoder;
        this.refreshTokenService=refreshTokenService;
        this.userService=userService;
    }
    /*
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
        }*/
    @Operation(summary = "Authenticate user", description = "Authenticates the user and returns a JWT token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User authenticated successfully"),
            @ApiResponse(responseCode = "401", description = "Invalid login credentials")
    })
    @PostMapping("/authenticate")
    public ResponseEntity<JWTToken> authorize(@Valid @RequestBody LoginVM loginVM) {
        // Usual authentication process
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginVM.getUsername(), loginVM.getPassword());

        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = createToken(authentication, loginVM.isRememberMe());
        Optional<User> userOptional = userService.getUserWithAuthoritiesByLogin(authentication.getName());
        if (!userOptional.isPresent()) {
            throw new RuntimeException("User not found");
        }
        User user = userOptional.get();

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setBearerAuth(jwt);
        JWTToken jwtToken = new JWTToken(jwt, refreshToken.getToken());
        return new ResponseEntity<>(jwtToken, httpHeaders, HttpStatus.OK);
    }
    @Operation(summary = "Refresh JWT Token", description = "Generates a new JWT access token using a valid refresh token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "New JWT access token generated successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid refresh token"),
            @ApiResponse(responseCode = "401", description = "Refresh token has expired or is invalid")
    })
    @PostMapping("/refresh-token")
    public ResponseEntity<JWTToken> refreshAccessToken(@RequestBody RefreshTokenVM refreshTokenVM) {
        String refreshToken = refreshTokenVM.getRefreshToken();

        RefreshToken existingToken = refreshTokenService.findByToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Refresh token not found"));
        refreshTokenService.verifyExpiration(existingToken);

        User user = userService.getUserById(existingToken.getUserId())
                .orElseThrow(() -> new RuntimeException("User not found"));

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                user.getLogin(), null, user.getAuthorities().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getName()))
                .collect(Collectors.toSet())
        );

        String newAccessToken = createToken(authentication, false);  // Don't use "rememberMe" for refresh tokens

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setBearerAuth(newAccessToken);
        return new ResponseEntity<>(new JWTToken(newAccessToken, refreshToken), httpHeaders, HttpStatus.OK);
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
            String authorities = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(" "));
            Instant now = Instant.now();
            Instant validity;
            if (rememberMe) {

                validity = now.plus(this.tokenValidityInSecondsForRememberMe, ChronoUnit.SECONDS);
            } else {

                validity = now.plus(this.tokenValidityInSeconds, ChronoUnit.SECONDS);
            }
            validity = validity.plus(1, ChronoUnit.SECONDS);
            JwtClaimsSet claims = JwtClaimsSet.builder()
                    .issuedAt(now)
                    .expiresAt(validity)
                    .subject(authentication.getName())
                    .claim(SecurityUtils.AUTHORITIES_KEY, authorities)
                    .build();
            JwsHeader jwsHeader = JwsHeader.with(SecurityUtils.JWT_ALGORITHM).build();
            String token = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims)).getTokenValue();
            Jwt decodedJwt = this.jwtDecoder.decode(token);
            return token;
        } catch (Exception e) {
            log.error("Error during JWT token creation: ", e);
            throw e;
        }
    }
/*
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
    }*/
}
