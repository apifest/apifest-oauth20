package com.apifest.oauth20;

public interface DBManager {
    boolean validClient(String clientId, String clientSecret);
    void storeClientCredentials(ClientCredentials clientCreds);
    void storeAuthCode(AuthCode authCode);
    void updateAuthCodeValidStatus(String authCode, boolean valid);
    void storeAccessToken(AccessToken accessToken);
    AccessToken findAccessTokenByRefreshToken(String refreshToken, String clientId);
    void updateAccessTokenValidStatus(String accessToken, boolean valid);
    AccessToken findAccessToken(String accessToken);
    AuthCode findAuthCode(String authCode, String redirectUri);
    ClientCredentials findClientCredentials(String clientId);
}
