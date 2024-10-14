package tn.solarchain.rest.error;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;

public class BadRequestAlertException extends ResponseStatusException {

    private static final long serialVersionUID = 1L;
    private final ProblemDetail problemDetail;

    public BadRequestAlertException(URI type, String title, String entityName, String errorKey) {
        super(HttpStatus.BAD_REQUEST, title);
        this.problemDetail = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        this.problemDetail.setType(type);
        this.problemDetail.setTitle(title);
        this.problemDetail.setDetail("An error occurred in entity: " + entityName);
        this.problemDetail.setProperty("errorKey", errorKey);
    }
    public BadRequestAlertException(String defaultMessage, String entityName, String errorKey) {
        this(URI.create("about:blank"), defaultMessage, entityName, errorKey); // Provide a default URI if not supplied
    }

    public ProblemDetail getProblemDetail() {
        return problemDetail;
    }
}
