package tn.solarchain.rest.error;

import org.springframework.http.HttpStatus;
import org.springframework.web.ErrorResponseException;
import tech.jhipster.web.rest.errors.ProblemDetailWithCause.ProblemDetailWithCauseBuilder;

@SuppressWarnings("java:S110")
public class InvalidPasswordException extends ErrorResponseException {

    private static final long serialVersionUID = 1L;

    public InvalidPasswordException() {
        super(
                HttpStatus.BAD_REQUEST,
                ProblemDetailWithCauseBuilder.instance()
                        .withStatus(HttpStatus.BAD_REQUEST.value())
                        .withType(ErrorConstants.INVALID_PASSWORD_TYPE)
                        .withTitle("Incorrect password")
                        .build(),
                null
        );
    }
}

