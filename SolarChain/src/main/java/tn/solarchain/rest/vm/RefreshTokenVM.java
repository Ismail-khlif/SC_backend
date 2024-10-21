package tn.solarchain.rest.vm;

public class RefreshTokenVM {

    private String refreshToken;

    public RefreshTokenVM() {
    }

    public RefreshTokenVM(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
