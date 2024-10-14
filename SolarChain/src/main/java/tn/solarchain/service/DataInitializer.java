package tn.solarchain.service;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import tn.solarchain.domain.Authority;
import tn.solarchain.domain.User;
import tn.solarchain.repository.AuthorityRepository;
import tn.solarchain.repository.UserRepository;
import tn.solarchain.security.AuthoritiesConstants;

import java.util.Set;

@Configuration
public class DataInitializer {

    @Bean
    public CommandLineRunner initData(
            PasswordEncoder encoder,
            UserRepository userRepository,
            AuthorityRepository authorityRepository) {
        return args -> {

            // Initialize roles
            String adminAuthority = AuthoritiesConstants.ADMIN;
            Authority authority = new Authority();
            authority.setName(adminAuthority);
            Authority adminRole = authorityRepository.findByName(adminAuthority)
                    .orElseGet(() -> authorityRepository.save(authority));

            // Create default user if not exists
            userRepository.findByLogin("admin").orElseGet(() -> {
                User user = new User();
                user.setLogin("admin");
                user.setEmail("admin@admin.com");
                user.setActivated(true);
                user.setPassword(encoder.encode("admin123"));
                user.setAuthorities(Set.of(adminRole)); // Assuming User class has a method to set roles
                return userRepository.save(user);
            });

        };
    }
}
