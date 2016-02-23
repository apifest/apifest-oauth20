package com.apifest.oauth20.persistence.cassandra;

import com.apifest.oauth20.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

/**
 * Created by Giovanni Baleani on 23/02/2016.
 */
public class CassandraDBManager implements DBManager {

    protected static Logger log = LoggerFactory.getLogger(DBManager.class);

    protected static final String KEYSPACE_NAME = "apifest";
    protected static final String CLIENTS_TABLE_NAME = "clients";
    protected static final String AUTH_CODE_TABLE_NAME = "auth_codes";
    protected static final String ACCESS_TOKEN_TABLE_NAME = "access_tokens";
    protected static final String SCOPE_TABLE_NAME = "scopes";


    @Override
    public boolean validClient(String clientId, String clientSecret) {
        return false;
    }

    @Override
    public void storeClientCredentials(ClientCredentials clientCreds) {
        //TODO: persist clientCreds obj into CLIENTS_TABLE_NAME
    }

    @Override
    public void storeAuthCode(AuthCode authCode) {
        //TODO: persist authCode obj into AUTH_CODE_TABLE_NAME
    }

    @Override
    public void updateAuthCodeValidStatus(String authCode, boolean valid) {
        //TODO: update valid flag by authCode key into AUTH_CODE_TABLE_NAME
        // 1. find 1 record by authCode
        // 2. update valid flag
    }

    @Override
    public void storeAccessToken(AccessToken accessToken) {
        //TODO: persist accessToken obj into ACCESS_TOKEN_TABLE_NAME
        // N.B. accessToken.token is the key... byt "findAccessTokenByRefreshToken" need to lookup by refreshToken and clientId
    }

    @Override
    public AccessToken findAccessTokenByRefreshToken(String refreshToken, String clientId) {
        // MongoDB performa a lookup into ACCESS_TOKEN_TABLE_NAME
        // using refreshToken and clientId as lookup key
        return null;
    }

    @Override
    public void updateAccessTokenValidStatus(String accessToken, boolean valid) {
        // ACCESS_TOKEN_TABLE_NAME
    }

    @Override
    public AccessToken findAccessToken(String accessToken) {
        // ACCESS_TOKEN_TABLE_NAME
        return null;
    }

    @Override
    public AuthCode findAuthCode(String authCode, String redirectUri) {
        // AUTH_CODE_TABLE_NAME
        return null;
    }

    @Override
    public ClientCredentials findClientCredentials(String clientId) {
        // CLIENTS_TABLE_NAME
        return null;
    }

    @Override
    public boolean storeScope(Scope scope) {
        // SCOPE_TABLE_NAME "scope" == key
        return false;
    }

    @Override
    public List<Scope> getAllScopes() {
        // SCOPE_TABLE_NAME
        return null;
    }

    @Override
    public Scope findScope(String scopeName) {
        // SCOPE_TABLE_NAME
        return null;
    }

    @Override
    public boolean updateClientApp(String clientId, String scope, String description, Integer status, Map<String, String> applicationDetails) {
        // update CLIENTS_TABLE_NAME using clientId as key
        return false;
    }

    @Override
    public List<ApplicationInfo> getAllApplications() {
        // CLIENTS_TABLE_NAME
        return null;
    }

    @Override
    public boolean deleteScope(String scopeName) {
        // SCOPE_TABLE_NAME
        return false;
    }

    @Override
    public List<AccessToken> getAccessTokenByUserIdAndClientApp(String userId, String clientId) {
        // ACCESS_TOKEN_TABLE_NAME
        return null;
    }

    @Override
    public void removeAccessToken(String accessToken) {
        // delete from ACCESS_TOKEN_TABLE_NAME using accessToken as key
    }
}
