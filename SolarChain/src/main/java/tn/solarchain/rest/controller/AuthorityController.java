package tn.solarchain.rest.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import tn.solarchain.domain.Authority;
import tn.solarchain.repository.AuthorityRepository;
import tn.solarchain.rest.error.BadRequestAlertException;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/authorities")
@Tag(name = "Authority", description = "API for managing authorities")
public class AuthorityController {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorityController.class);

    private final AuthorityRepository authorityRepository;

    public AuthorityController(AuthorityRepository authorityRepository) {
        this.authorityRepository = authorityRepository;
    }
    @Operation(summary = "Create a new authority", description = "Creates a new authority and saves it in the system")
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Authority successfully created"),
            @ApiResponse(responseCode = "400", description = "Authority already exists")
    })
    @PostMapping("")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    public ResponseEntity<Authority> createAuthority(@Valid @RequestBody Authority authority) throws URISyntaxException {
        LOG.debug("REST request to save Authority : {}", authority);
        if (authorityRepository.existsById(authority.getName())) {
            throw new BadRequestAlertException("authority already exists", "adminAuthority", "idexists");
        }
        authority = authorityRepository.save(authority);
        URI location = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}")
                .buildAndExpand(authority.getName()).toUri();
        return ResponseEntity.created(location).body(authority);
    }
    @Operation(summary = "Get all authorities", description = "Retrieves a list of all authorities")
    @ApiResponse(responseCode = "200", description = "Successfully retrieved all authorities")
    @GetMapping("")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    public List<Authority> getAllAuthorities() {
        LOG.debug("REST request to get all Authorities");
        return authorityRepository.findAll();
    }
    @Operation(summary = "Get an authority by ID", description = "Retrieves an authority by its ID")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Successfully retrieved the authority"),
            @ApiResponse(responseCode = "404", description = "Authority not found")
    })
    @GetMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    public ResponseEntity<Authority> getAuthority(@PathVariable("id") String id) {
        LOG.debug("REST request to get Authority : {}", id);
        Optional<Authority> authority = authorityRepository.findById(id);
        return authority.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }
    @Operation(summary = "Delete an authority", description = "Deletes an authority by its ID")
    @ApiResponse(responseCode = "204", description = "Authority successfully deleted")
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    public ResponseEntity<Void> deleteAuthority(@PathVariable("id") String id) {
        LOG.debug("REST request to delete Authority : {}", id);
        authorityRepository.deleteById(id);
        return ResponseEntity.noContent().build();
    }
}
