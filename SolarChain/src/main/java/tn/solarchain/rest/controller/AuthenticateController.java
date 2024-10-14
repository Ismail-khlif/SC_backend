package tn.solarchain.rest.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import tn.solarchain.domain.User;
import tn.solarchain.repository.UserRepository;
import tn.solarchain.rest.vm.LoginVM;
import jakarta.validation.Valid;
import java.security.Principal;
import java.util.List;
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
import tn.solarchain.security.UserDetailsImpl;
import tn.solarchain.security.jwt.JwtUtils;

import static org.reflections.Reflections.log;

/**
 * Controller to authenticate users.
 */
@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "Operations related to user authentication")
public class AuthenticateController {

    private static final Logger LOG = LoggerFactory.getLogger(AuthenticateController.class);



    @Autowired
    JwtUtils jwtUtils;

    private final PasswordEncoder encoder;;
    private final AuthenticationManager authenticationManager;

    @Value("${jwt.token.validity.in.seconds:0}")
    private long tokenValidityInSeconds;

    @Value("${jwt.token.validity.in.seconds.for.remember.me:0}")
    private long tokenValidityInSecondsForRememberMe;
    @Autowired
    private UserRepository userRepository;

    public AuthenticateController( PasswordEncoder encoder, AuthenticationManager authenticationManager) {
        this.encoder = encoder;
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

            User user = userRepository.findByLogin(loginVM.getUsername()).orElseThrow();
            UserDetailsImpl userDetails = UserDetailsImpl.build(user);
            List<GrantedAuthority> authorities = user.getAuthorities().stream()
                    .map(role -> new SimpleGrantedAuthority(role.getName()))
                    .collect(Collectors.toList());

            Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, loginVM.getPassword(), authorities);
            String jwt = jwtUtils.generateJwtToken(authentication);

            log.info("Attempting authentication for user: {}", loginVM.getUsername());
           // Authentication authentication = authenticationManager.authenticate(authenticationToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            //String jwt = this.createToken(authentication, loginVM.isRememberMe());
            log.info("JWT Token created for user: {}", loginVM.getUsername());

            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.setBearerAuth(jwt);
            return new ResponseEntity<>(new JWTToken(jwt), httpHeaders, HttpStatus.OK);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
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

//    public String createToken(Authentication authentication, boolean rememberMe) {
//        String authorities = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(" "));
//
//        Instant now = Instant.now();
//        Instant validity;
//        if (rememberMe) {
//            validity = now.plus(this.tokenValidityInSecondsForRememberMe, ChronoUnit.SECONDS);
//        } else {
//            validity = now.plus(this.tokenValidityInSeconds, ChronoUnit.SECONDS);
//        }
//
//        JwtClaimsSet claims = JwtClaimsSet.builder()
//                .issuedAt(now)
//                .expiresAt(validity)
//                .subject(authentication.getName())
//                .claim(SecurityUtils.AUTHORITIES_KEY, authorities)
//                .build();
//
//        JwsHeader jwsHeader = JwsHeader.with(SecurityUtils.JWT_ALGORITHM).build();
//        return this.encoder.encode(JwtEncoderParameters.from(jwsHeader, claims).toString()).getTokenValue();
//    }

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
