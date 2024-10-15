package tn.solarchain.rest.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.data.web.PageableDefault;
import tn.solarchain.service.UserService;
import tn.solarchain.service.dto.UserDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.util.*;

@RestController
@RequestMapping("/api")
@Tag(name = "Public User", description = "API for public user information")
public class PublicUserResource {

    private static final List<String> ALLOWED_ORDERED_PROPERTIES = Arrays.asList("id", "login", "firstName", "lastName", "email", "activated", "langKey");

    private static final Logger LOG = LoggerFactory.getLogger(PublicUserResource.class);

    private final UserService userService;

    public PublicUserResource(UserService userService) {
        this.userService = userService;
    }


    @Operation(summary = "Get all public users", description = "Retrieves a list of all public users")
    @ApiResponse(responseCode = "200", description = "Successfully retrieved public users")
    @GetMapping("/users")
    public ResponseEntity<List<UserDTO>> getAllPublicUsers(@Parameter(hidden = true) @PageableDefault(size = 10) Pageable pageable) {
        LOG.debug("REST request to get all public User names");
        if (!onlyContainsAllowedProperties(pageable)) {
            return ResponseEntity.badRequest().build();
        }

        final Page<UserDTO> page = userService.getAllPublicUsers(pageable);
        HttpHeaders headers = generatePaginationHttpHeaders(ServletUriComponentsBuilder.fromCurrentRequest(), page);
        return new ResponseEntity<>(page.getContent(), headers, HttpStatus.OK);
    }

    private boolean onlyContainsAllowedProperties(Pageable pageable) {
        return pageable.getSort().stream().map(Sort.Order::getProperty).allMatch(ALLOWED_ORDERED_PROPERTIES::contains);
    }

    private HttpHeaders generatePaginationHttpHeaders(ServletUriComponentsBuilder uriBuilder, Page<?> page) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("X-Total-Count", Long.toString(page.getTotalElements()));
        String link = "";
        if (page.getNumber() + 1 < page.getTotalPages()) {
            link = "<" + uriBuilder.replaceQueryParam("page", page.getNumber() + 1)
                    .replaceQueryParam("size", page.getSize()).toUriString() + ">; rel=\"next\",";
        }
        // Add previous link if applicable
        if (page.getNumber() > 0) {
            link += "<" + uriBuilder.replaceQueryParam("page", page.getNumber() - 1)
                    .replaceQueryParam("size", page.getSize()).toUriString() + ">; rel=\"prev\",";
        }
        headers.add(HttpHeaders.LINK, link);
        return headers;
    }
}
