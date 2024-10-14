package tn.solarchain.rest.error;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class InvalidPasswordException extends ResponseStatusException {

    private static final long serialVersionUID = 1L;

    public InvalidPasswordException() {
        super(HttpStatus.BAD_REQUEST, "Incorrect password");
    }
}
