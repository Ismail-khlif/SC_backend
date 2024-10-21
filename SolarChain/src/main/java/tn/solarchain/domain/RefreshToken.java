package tn.solarchain.domain;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import java.time.Instant;

@Document(collection = "refresh_token")
public class RefreshToken {

    @Id
    private String id;

    private String token;

    private Instant expiryDate;

    private String userId;

    // Constructors, Getters, and Setters
    public RefreshToken() {}

    public RefreshToken(String token, Instant expiryDate, String userId) {
        this.token = token;
        this.expiryDate = expiryDate;
        this.userId = userId;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public Instant getExpiryDate() {
        return expiryDate;
    }

    public void setExpiryDate(Instant expiryDate) {
        this.expiryDate = expiryDate;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }
}
