package tn.solarchain.service;

import org.springframework.data.domain.Pageable;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import tn.solarchain.config.Constants;
import tn.solarchain.domain.Authority;
import tn.solarchain.domain.User;
import tn.solarchain.repository.AuthorityRepository;
import tn.solarchain.repository.UserRepository;
import tn.solarchain.rest.error.EmailAlreadyUsedException;
import tn.solarchain.rest.error.InvalidPasswordException;
import tn.solarchain.rest.error.UsernameAlreadyUsedException;
import tn.solarchain.security.AuthoritiesConstants;
import tn.solarchain.security.SecurityUtils;
import tn.solarchain.service.dto.AdminUserDTO;
import tn.solarchain.service.dto.UserDTO;

@Service
public class UserService {

    private static final Logger LOG = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthorityRepository authorityRepository;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, AuthorityRepository authorityRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authorityRepository = authorityRepository;
    }

    public Optional<User> activateRegistration(String key) {
        LOG.debug("Activating user for activation key {}", key);
        return userRepository
                .findOneByActivationKey(key)
                .map(user -> {
                    user.setActivated(true);
                    user.setActivationKey(null);
                    userRepository.save(user);
                    LOG.debug("Activated user: {}", user);
                    return user;
                });
    }

    public Optional<User> completePasswordReset(String newPassword, String key) {
        LOG.debug("Reset user password for reset key {}", key);
        return userRepository
                .findOneByResetKey(key)
                .filter(user -> user.getResetDate().isAfter(Instant.now().minus(1, ChronoUnit.DAYS)))
                .map(user -> {
                    user.setPassword(passwordEncoder.encode(newPassword));
                    user.setResetKey(null);
                    user.setResetDate(null);
                    userRepository.save(user);
                    return user;
                });
    }

    public Optional<User> requestPasswordReset(String email) {
        return userRepository
                .findOneByEmailIgnoreCase(email)
                .filter(User::isActivated)
                .map(user -> {
                    user.setResetKey(UUID.randomUUID().toString());  // Use UUID for reset key
                    user.setResetDate(Instant.now());
                    userRepository.save(user);
                    return user;
                });
    }

    public User registerUser(AdminUserDTO userDTO, String password) {
        userRepository
                .findOneByLogin(userDTO.getLogin().toLowerCase())
                .ifPresent(existingUser -> {
                    boolean removed = removeNonActivatedUser(existingUser);
                    if (!removed) {
                        throw new UsernameAlreadyUsedException();
                    }
                });
        userRepository
                .findOneByEmailIgnoreCase(userDTO.getEmail())
                .ifPresent(existingUser -> {
                    boolean removed = removeNonActivatedUser(existingUser);
                    if (!removed) {
                        throw new EmailAlreadyUsedException();
                    }
                });

        User newUser = new User();
        String encryptedPassword = passwordEncoder.encode(password);
        newUser.setLogin(userDTO.getLogin().toLowerCase());
        newUser.setPassword(encryptedPassword);
        newUser.setFirstName(userDTO.getFirstName());
        newUser.setLastName(userDTO.getLastName());
        newUser.setEmail(userDTO.getEmail().toLowerCase());
        newUser.setActivated(false);
        newUser.setActivationKey(UUID.randomUUID().toString());  // Use UUID for activation key

        // Add authorities
        Set<Authority> authorities = new HashSet<>();
        authorityRepository.findById(AuthoritiesConstants.USER).ifPresent(authorities::add);  // Use AuthoritiesConstants
        newUser.setAuthorities(authorities);

        userRepository.save(newUser);
        LOG.debug("Created Information for User: {}", newUser);
        return newUser;
    }

    private boolean removeNonActivatedUser(User existingUser) {
        if (existingUser.isActivated()) {
            return false;
        }
        userRepository.delete(existingUser);
        return true;
    }

    public User createUser(AdminUserDTO userDTO) {
        User user = new User();
        user.setLogin(userDTO.getLogin().toLowerCase());
        user.setFirstName(userDTO.getFirstName());
        user.setLastName(userDTO.getLastName());
        user.setEmail(userDTO.getEmail().toLowerCase());
        String encryptedPassword = passwordEncoder.encode(UUID.randomUUID().toString());
        user.setPassword(encryptedPassword);
        user.setResetKey(UUID.randomUUID().toString());
        user.setResetDate(Instant.now());
        user.setActivated(true);

        if (userDTO.getAuthorities() != null) {
            Set<Authority> authorities = userDTO
                    .getAuthorities()
                    .stream()
                    .map(authorityRepository::findById)
                    .filter(Optional::isPresent)
                    .map(Optional::get)
                    .collect(Collectors.toSet());
            user.setAuthorities(authorities);
        }

        userRepository.save(user);
        LOG.debug("Created Information for User: {}", user);
        return user;
    }
    public Page<UserDTO> getAllPublicUsers(Pageable pageable) {
        return userRepository.findAllByIdNotNullAndActivatedIsTrue(pageable)
                .map(user -> new UserDTO(user));
    }

    public Optional<AdminUserDTO> updateUser(AdminUserDTO userDTO) {
        return userRepository.findById(userDTO.getId())
                .map(user -> {
                    user.setLogin(userDTO.getLogin().toLowerCase());
                    user.setFirstName(userDTO.getFirstName());
                    user.setLastName(userDTO.getLastName());
                    user.setEmail(userDTO.getEmail().toLowerCase());
                    user.setImageUrl(userDTO.getImageUrl());
                    user.setActivated(userDTO.isActivated());
                    user.setLangKey(userDTO.getLangKey() != null ? userDTO.getLangKey() : Constants.DEFAULT_LANGUAGE); // Use Constants

                    // Update authorities
                    Set<Authority> managedAuthorities = user.getAuthorities();
                    managedAuthorities.clear();
                    userDTO
                            .getAuthorities()
                            .stream()
                            .map(authorityRepository::findById)
                            .filter(Optional::isPresent)
                            .map(Optional::get)
                            .forEach(managedAuthorities::add);

                    userRepository.save(user);
                    LOG.debug("Changed Information for User: {}", user);
                    return new AdminUserDTO(user);
                });
    }

    public void deleteUser(String login) {
        userRepository
                .findOneByLogin(login)
                .ifPresent(user -> {
                    userRepository.delete(user);
                    LOG.debug("Deleted User: {}", user);
                });
    }

    public void updateUser(String firstName, String lastName, String email, String langKey, String imageUrl) {
        SecurityUtils.getCurrentUserLogin()
                .flatMap(userRepository::findOneByLogin)
                .ifPresent(user -> {
                    user.setFirstName(firstName);
                    user.setLastName(lastName);
                    if (email != null) {
                        user.setEmail(email.toLowerCase());
                    }
                    user.setLangKey(langKey != null ? langKey : Constants.DEFAULT_LANGUAGE);  // Use Constants for default language
                    user.setImageUrl(imageUrl);
                    userRepository.save(user);
                    LOG.debug("Changed Information for User: {}", user);
                });
    }

    public void changePassword(String currentClearTextPassword, String newPassword) {
        SecurityUtils.getCurrentUserLogin()
                .flatMap(userRepository::findOneByLogin)
                .ifPresent(user -> {
                    String currentEncryptedPassword = user.getPassword();
                    if (!passwordEncoder.matches(currentClearTextPassword, currentEncryptedPassword)) {
                        throw new InvalidPasswordException();
                    }
                    String encryptedPassword = passwordEncoder.encode(newPassword);
                    user.setPassword(encryptedPassword);
                    userRepository.save(user);
                    LOG.debug("Changed password for User: {}", user);
                });
    }

    public Optional<User> getUserWithAuthorities() {
        return SecurityUtils.getCurrentUserLogin()
                .flatMap(userRepository::findOneByLogin);
    }
    public Optional<User> getUserWithAuthoritiesByLogin(String login) {
        return userRepository.findOneByLogin(login);
    }
    public Page<AdminUserDTO> getAllManagedUsers(Pageable pageable) {
        return userRepository.findAll(pageable).map(AdminUserDTO::new);
    }

    @Scheduled(cron = "0 0 1 * * ?")
    public void removeNotActivatedUsers() {
        userRepository
                .findAllByActivatedIsFalseAndActivationKeyIsNotNullAndCreatedDateBefore(Instant.now().minus(3, ChronoUnit.DAYS))
                .forEach(user -> {
                    LOG.debug("Deleting not activated user {}", user.getLogin());
                    userRepository.delete(user);
                });
    }

    public List<String> getAuthorities() {
        return authorityRepository.findAll().stream().map(Authority::getName).toList();
    }
    public Optional<User> getUserById(String userId) {
        return userRepository.findById(userId);
    }
}


