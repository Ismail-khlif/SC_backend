package tn.solarchain.service.dto;

public class JWTToken {

    private String idToken;
    private String refreshToken;

    public JWTToken(String idToken, String refreshToken) {
        this.idToken = idToken;
        this.refreshToken = refreshToken;
    }

    public String getIdToken() {
        return idToken;
    }

    public void setIdToken(String idToken) {
        this.idToken = idToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    @Override
    public String toString() {
        return "JWTToken{" +
                "idToken='" + idToken + '\'' +
                ", refreshToken='" + refreshToken + '\'' +
                '}';
    }
}
