package tn.solarchain.security;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import tn.solarchain.repository.UserRepository;
import tn.solarchain.domain.User;

import java.util.Optional;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.reflections.Reflections.log;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private static final Logger log = LoggerFactory.getLogger(CustomUserDetailsService.class); // Use SLF4J logger

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("Attempting to load user by username: {}", username);

        Optional<User> userOptional = userRepository.findByLogin(username);

        if (userOptional.isEmpty()) {
            log.warn("User not found for username: {}", username);
            throw new UsernameNotFoundException("User not found: " + username);
        }

        User user = userOptional.get();

        log.info("User found: {}", user.getLogin());
        log.info("User password: {}", user.getPassword()); // This should be a hashed password
        log.info("User authorities: {}", user.getAuthorities());

        return org.springframework.security.core.userdetails.User
                .withUsername(user.getLogin())
                .password(user.getPassword())
                .authorities(user.getAuthorities().stream()
                        .map(authority -> authority.getName()) // Assuming getName() retrieves the role
                        .collect(Collectors.toList()).toArray(new String[0])) // Authorities are returned as strings
                .build();
    }
}

