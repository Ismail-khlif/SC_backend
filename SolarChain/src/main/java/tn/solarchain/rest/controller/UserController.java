package tn.solarchain.rest.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import tn.solarchain.config.Constants;
import tn.solarchain.domain.User;
import tn.solarchain.repository.UserRepository;
import tn.solarchain.security.AuthoritiesConstants;
import tn.solarchain.service.MailService;
import tn.solarchain.service.UserService;
import tn.solarchain.service.dto.AdminUserDTO;
import tn.solarchain.rest.error.BadRequestAlertException;
import tn.solarchain.rest.error.EmailAlreadyUsedException;
import tn.solarchain.rest.error.LoginAlreadyUsedException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Pattern;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;
import java.util.List;
import java.util.Collections;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

@RestController
@RequestMapping("/api/admin")
@Tag(name = "User Management", description = "Operations pertaining to user management in the system")
public class UserController {

    private static final List<String> ALLOWED_ORDERED_PROPERTIES = Collections.unmodifiableList(
            List.of("id", "login", "firstName", "lastName", "email", "activated", "langKey", "createdBy",
                    "createdDate", "lastModifiedBy", "lastModifiedDate")
    );

    private static final Logger LOG = LoggerFactory.getLogger(UserController.class);
    private final UserService userService;
    private final UserRepository userRepository;
    private final MailService mailService;

    public UserController(UserService userService, UserRepository userRepository, MailService mailService) {
        this.userService = userService;
        this.userRepository = userRepository;
        this.mailService = mailService;
    }

    // Create new user
    @Operation(summary = "Create a new user", description = "Creates a new user and sends a creation email")
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "User successfully created"),
            @ApiResponse(responseCode = "400", description = "Bad request, user data is invalid")
    })
    @PostMapping("/users")
    @PreAuthorize("hasAuthority('" + AuthoritiesConstants.ADMIN + "')")
    public ResponseEntity<User> createUser(@Valid @RequestBody AdminUserDTO userDTO) throws URISyntaxException {
        LOG.debug("REST request to save User : {}", userDTO);

        if (userDTO.getId() != null) {
            throw new BadRequestAlertException("A new user cannot already have an ID", "userManagement", "idexists");
        } else if (userRepository.findOneByLogin(userDTO.getLogin().toLowerCase()).isPresent()) {
            throw new LoginAlreadyUsedException();
        } else if (userRepository.findOneByEmailIgnoreCase(userDTO.getEmail()).isPresent()) {
            throw new EmailAlreadyUsedException();
        } else {
            User newUser = userService.createUser(userDTO);
            mailService.sendCreationEmail(newUser);
            URI location = UriComponentsBuilder
                    .fromPath("/api/admin/users/{login}")
                    .buildAndExpand(newUser.getLogin())
                    .toUri();

            HttpHeaders headers = createAlert("User created", newUser.getLogin());
            return ResponseEntity.created(location).headers(headers).body(newUser);
        }
    }

    // Update existing user
    @Operation(summary = "Update an existing user", description = "Updates the details of an existing user")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "User successfully updated"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    @PutMapping({ "/users", "/users/{login}" })
    @PreAuthorize("hasAuthority('" + AuthoritiesConstants.ADMIN + "')")
    public ResponseEntity<AdminUserDTO> updateUser(
            @PathVariable(name = "login", required = false) @Pattern(regexp = Constants.LOGIN_REGEX) String login,
            @Valid @RequestBody AdminUserDTO userDTO
    ) {
        LOG.debug("REST request to update User : {}", userDTO);
        Optional<User> existingUser = userRepository.findOneByEmailIgnoreCase(userDTO.getEmail());
        if (existingUser.isPresent() && !existingUser.get().getId().equals(userDTO.getId())) {
            throw new EmailAlreadyUsedException();
        }
        existingUser = userRepository.findOneByLogin(userDTO.getLogin().toLowerCase());
        if (existingUser.isPresent() && !existingUser.get().getId().equals(userDTO.getId())) {
            throw new LoginAlreadyUsedException();
        }
        Optional<AdminUserDTO> updatedUser = userService.updateUser(userDTO);
        HttpHeaders headers = createAlert("User updated", userDTO.getLogin());
        return updatedUser.map(user -> ResponseEntity.ok().headers(headers).body(user))
                .orElse(ResponseEntity.notFound().build());
    }

    // Get all users with pagination
    @Operation(summary = "Get all users", description = "Retrieves a list of all users with pagination")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Successfully retrieved users list"),
            @ApiResponse(responseCode = "400", description = "Bad request, invalid query")
    })
    @GetMapping("/users")
    @PreAuthorize("hasAuthority('" + AuthoritiesConstants.ADMIN + "')")
    public ResponseEntity<List<AdminUserDTO>> getAllUsers(Pageable pageable) {
        LOG.debug("REST request to get all Users for admin");
        if (!onlyContainsAllowedProperties(pageable)) {
            return ResponseEntity.badRequest().build();
        }

        Page<AdminUserDTO> page = userService.getAllManagedUsers(pageable);
        HttpHeaders headers = generatePaginationHttpHeaders(ServletUriComponentsBuilder.fromCurrentRequest(), page);
        return new ResponseEntity<>(page.getContent(), headers, HttpStatus.OK);
    }

    // Get user by login
    @Operation(summary = "Get a user by login", description = "Retrieves a user by their login ID")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Successfully retrieved user"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    @GetMapping("/users/{login}")
    @PreAuthorize("hasAuthority('" + AuthoritiesConstants.ADMIN + "')")
    public ResponseEntity<AdminUserDTO> getUser(@PathVariable("login") @Pattern(regexp = Constants.LOGIN_REGEX) String login) {
        LOG.debug("REST request to get User : {}", login);
        return userService.getUserWithAuthoritiesByLogin(login)
                .map(AdminUserDTO::new)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // Delete user by login
    @Operation(summary = "Delete a user", description = "Deletes a user by their login ID")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "User successfully deleted"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    @DeleteMapping("/users/{login}")
    @PreAuthorize("hasAuthority('" + AuthoritiesConstants.ADMIN + "')")
    public ResponseEntity<Void> deleteUser(@PathVariable("login") @Pattern(regexp = Constants.LOGIN_REGEX) String login) {
        LOG.debug("REST request to delete User: {}", login);
        userService.deleteUser(login);
        HttpHeaders headers = createAlert("User deleted", login);
        return ResponseEntity.noContent().headers(headers).build();
    }

    // Helper to check sorting properties
    private boolean onlyContainsAllowedProperties(Pageable pageable) {
        return pageable.getSort().stream().map(Sort.Order::getProperty).allMatch(ALLOWED_ORDERED_PROPERTIES::contains);
    }

    // Helper to generate pagination headers
    private HttpHeaders generatePaginationHttpHeaders(ServletUriComponentsBuilder uriBuilder, Page<?> page) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("X-Total-Count", Long.toString(page.getTotalElements()));
        String link = "";
        if (page.getNumber() + 1 < page.getTotalPages()) {
            link = "<" + uriBuilder.replaceQueryParam("page", page.getNumber() + 1)
                    .replaceQueryParam("size", page.getSize()).toUriString() + ">; rel=\"next\",";
        }
        if (page.getNumber() > 0) {
            link += "<" + uriBuilder.replaceQueryParam("page", page.getNumber() - 1)
                    .replaceQueryParam("size", page.getSize()).toUriString() + ">; rel=\"prev\",";
        }
        headers.add(HttpHeaders.LINK, link);
        return headers;
    }

    // Helper to create alert headers
    private HttpHeaders createAlert(String message, String param) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("X-application-alert", message);
        headers.add("X-application-params", param);
        return headers;
    }
}
