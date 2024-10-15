package tn.solarchain.config;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import org.springframework.security.web.SecurityFilterChain;
import tn.solarchain.security.CustomUserDetailsService;

import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;


@Configuration
@EnableMethodSecurity
public class SecurityConfiguration {


    private final CustomUserDetailsService customUserDetailsService;
    public SecurityConfiguration(CustomUserDetailsService customUserDetailsService) {
        this.customUserDetailsService = customUserDetailsService;
    }
    private final Logger log = LoggerFactory.getLogger(SecurityConfiguration.class);

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.algorithm:HmacSHA512}")
    private String jwtAlgorithm;
    @Value("${jwt.token-validity-in-seconds:3600}")
    private long tokenValidityInSeconds;


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtEncoder jwtEncoder() {
        SecretKey secretKey = new SecretKeySpec(getDecodedSecret(), jwtAlgorithm);
        System.out.println("JWT Encoder using SecretKey (Algorithm: " + jwtAlgorithm + "): " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));
        System.out.println(getDecodedSecret());
        JwtEncoder encoder = new NimbusJwtEncoder(new ImmutableSecret<>(secretKey));

        return new JwtEncoder() {
            @Override
            public Jwt encode(JwtEncoderParameters parameters) throws JwtException {
                System.out.println("Encoding JWT with Claims: " + parameters.getClaims());
                Jwt jwt = encoder.encode(parameters);
                System.out.println("JWT Token successfully created: " + jwt.getTokenValue());
                return jwt;
            }
        };
    }
    @Bean
    public JwtDecoder jwtDecoder() {
        SecretKey secretKey = new SecretKeySpec(getDecodedSecret(), jwtAlgorithm);

        // Log the algorithm and the encoded secret key
        System.out.println("JWT Decoder using SecretKey (Algorithm: " + jwtAlgorithm + "): " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));
        System.out.println("Decoded Secret Key (Raw Bytes): " + Arrays.toString(getDecodedSecret())); // Log the raw secret key bytes

        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withSecretKey(secretKey).macAlgorithm(MacAlgorithm.HS512).build();


        return new JwtDecoder() {
            @Override
            public Jwt decode(String token) throws JwtException {
                System.out.println("Decoding JWT Token: " + token);
                try {
                    // First step: Log token details before decoding
                    String[] tokenParts = token.split("\\.");
                    System.out.println("Header (Base64-encoded): " + tokenParts[0]);
                    System.out.println("Payload (Base64-encoded): " + tokenParts[1]);
                    System.out.println("Signature (Base64-encoded): " + tokenParts[2]);

                    // Second step: Decoding token using Nimbus JWT Decoder
                    Jwt decodedJwt = jwtDecoder.decode(token);

                    // Log after successfully decoding the token
                    System.out.println("Decoded JWT Claims: " + decodedJwt.getClaims());
                    System.out.println("Decoded JWT Header: " + decodedJwt.getHeaders());
                    System.out.println("Decoded JWT Subject: " + decodedJwt.getSubject());
                    System.out.println("Decoded JWT Issuer: " + decodedJwt.getIssuer());

                    // Log the expiration and issued time (if present)
                    if (decodedJwt.getExpiresAt() != null) {
                        System.out.println("JWT Expiration Time: " + decodedJwt.getExpiresAt());
                    }
                    if (decodedJwt.getIssuedAt() != null) {
                        System.out.println("JWT Issued At: " + decodedJwt.getIssuedAt());
                    }

                    return decodedJwt;
                } catch (JwtException e) {
                    // Log the exception details
                    System.out.println("Failed to decode JWT Token: " + e.getMessage());
                    e.printStackTrace(); // Print the stack trace for deeper inspection
                    throw e;
                }
            }
        };
    }


    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthorityPrefix("");
        grantedAuthoritiesConverter.setAuthoritiesClaimName("auth");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }

    @Bean
    public BearerTokenResolver bearerTokenResolver() {
        var bearerTokenResolver = new DefaultBearerTokenResolver();
        bearerTokenResolver.setAllowUriQueryParameter(true);
        return bearerTokenResolver;
    }
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        log.info("Configuring DaoAuthenticationProvider with CustomUserDetailsService");

        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(customUserDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder()); // Define this as a bean elsewhere
        return authProvider;
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeHttpRequests()
                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**", "/swagger-ui.html").permitAll()
                .requestMatchers("/api/authenticate").permitAll()
                .anyRequest().authenticated()
                .and()
                .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(jwtAuthenticationConverter());
        return http.build();
    }

    private byte[] getDecodedSecret() {

        return java.util.Base64.getDecoder().decode(jwtSecret);  // Decode the Base64-encoded secret key
    }

}
