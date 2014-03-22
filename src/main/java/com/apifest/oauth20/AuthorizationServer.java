/*
* Copyright 2013-2014, ApiFest project
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

package com.apifest.oauth20;

import java.io.IOException;
import java.nio.charset.Charset;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.QueryStringDecoder;
import org.jboss.netty.handler.codec.http.QueryStringEncoder;
import org.jboss.netty.util.CharsetUtil;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Main class for authorization.
 *
 * @author Rossitsa Borissova
 */
public class AuthorizationServer {

    private static final String APPNAME_PARAMETER = "app_name";
    static final String BASIC = "Basic ";
    private static final String TOKEN_TYPE_BEARER = "Bearer";

    protected static Logger log = LoggerFactory.getLogger(AuthorizationServer.class);

    protected DBManager db = DBManagerFactory.getInstance();

    public ClientCredentials issueClientCredentials(HttpRequest req) throws OAuthException {
        QueryStringDecoder dec = new QueryStringDecoder(req.getUri());
        ClientCredentials creds = null;
        if(dec.getParameters() != null && dec.getParameters().get(APPNAME_PARAMETER) != null) {
            String appName = dec.getParameters().get(APPNAME_PARAMETER).get(0);
            creds = new ClientCredentials(appName);
            db.storeClientCredentials(creds);
        } else {
            throw new OAuthException(Response.APPNAME_IS_NULL, HttpResponseStatus.BAD_REQUEST);
        }
        return creds;
    }

    // /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
    public String issueAuthorizationCode(HttpRequest req) throws OAuthException {
        AuthRequest authRequest = new AuthRequest(req);
        log.debug("received client_id:" + authRequest.getClientId());
        if(!isValidClientId(authRequest.getClientId())){
            throw new OAuthException(Response.INVALID_CLIENT_ID, HttpResponseStatus.BAD_REQUEST);
        }
        authRequest.validate();

        AuthCode authCode = new AuthCode(generateCode(), authRequest.getClientId(), authRequest.getRedirectUri(),
                authRequest.getState(), authRequest.getScope(), authRequest.getResponseType(), authRequest.getUserId());
        log.debug("authCode: {}", authCode.getCode());
        db.storeAuthCode(authCode);

        // return redirect URI, append param code=[Authcode]
        QueryStringEncoder enc = new QueryStringEncoder(authRequest.getRedirectUri());
        enc.addParam("code", authCode.getCode());
        return enc.toString();
    }

    public AccessToken issueAccessToken(HttpRequest req) throws OAuthException {
        String clientId = getBasicAuthorizationClientId(req);
        if(clientId == null){
            throw new OAuthException(Response.INVALID_CLIENT_ID, HttpResponseStatus.BAD_REQUEST);
        }
        TokenRequest tokenRequest = new TokenRequest(req);
        tokenRequest.setClientId(clientId);

        /*if(!isValidClientId(tokenRequest.getClientId())){
            throw new OAuthException(ErrorResponse.INVALID_CLIENT_ID, HttpResponseStatus.BAD_REQUEST);
        }*/
        tokenRequest.validate();

        AccessToken accessToken = null;
        if(TokenRequest.AUTHORIZATION_CODE.equals(tokenRequest.getGrantType())) {
            AuthCode authCode = findAuthCode(tokenRequest);
            // TODO: REVISIT: Move client_id check to db query
            if(authCode != null) {
                if(!tokenRequest.getClientId().equals(authCode.getClientId())) {
                    throw new OAuthException(Response.INVALID_CLIENT_ID, HttpResponseStatus.BAD_REQUEST);
                }
                if(authCode.getRedirectUri() != null &&
                        !tokenRequest.getRedirectUri().equals(authCode.getRedirectUri())){
                    throw new OAuthException(Response.INVALID_REDIRECT_URI, HttpResponseStatus.BAD_REQUEST);
                } else {
                    // invalidate the auth code
                    db.updateAuthCodeValidStatus(authCode.getCode(), false);
                    accessToken = new AccessToken(TOKEN_TYPE_BEARER, "599", authCode.getScope());
                    accessToken.setUserId(authCode.getUserId());
                    accessToken.setClientId(authCode.getClientId());
                    accessToken.setCodeId(authCode.getId());
                    db.storeAccessToken(accessToken);
                }
            } else {
                throw new OAuthException(Response.INVALID_AUTH_CODE, HttpResponseStatus.BAD_REQUEST);
            }
        } else if(TokenRequest.REFRESH_TOKEN.equals(tokenRequest.getGrantType())) {
            accessToken = db.findAccessTokenByRefreshToken(tokenRequest.getRefreshToken(), tokenRequest.getClientId());
            if(accessToken != null) {
                db.updateAccessTokenValidStatus(accessToken.getToken(), false);
                AccessToken newAccessToken = new AccessToken(TOKEN_TYPE_BEARER, getExpiresIn(TokenRequest.PASSWORD), accessToken.getScope());
                newAccessToken.setUserId(accessToken.getUserId());
                newAccessToken.setClientId(accessToken.getClientId());
                db.storeAccessToken(newAccessToken);
                return newAccessToken;
            } else {
                throw new OAuthException(Response.INVALID_REFRESH_TOKEN, HttpResponseStatus.BAD_REQUEST);
            }
        } else if(TokenRequest.CLIENT_CREDENTIALS.equals(tokenRequest.getGrantType())) {
            accessToken = new AccessToken(TOKEN_TYPE_BEARER, getExpiresIn(TokenRequest.CLIENT_CREDENTIALS),
                    tokenRequest.getScope(), false);
            accessToken.setClientId(tokenRequest.getClientId());
            db.storeAccessToken(accessToken);
        } else if(TokenRequest.PASSWORD.equals(tokenRequest.getGrantType())) {
            accessToken = new AccessToken(TOKEN_TYPE_BEARER, getExpiresIn(TokenRequest.PASSWORD),
                    tokenRequest.getScope());
            try {
                String userId = authenticateUser(tokenRequest.getUsername(), tokenRequest.getPassword());
                if(userId != null) {
                    accessToken.setUserId(userId);
                    accessToken.setClientId(tokenRequest.getClientId());
                    db.storeAccessToken(accessToken);
                } else {
                    throw new OAuthException(Response.INVALID_USERNAME_PASSWORD, HttpResponseStatus.UNAUTHORIZED);
                }
            } catch (IOException e) {
                log.error("Cannot authenticate user", e);
                throw new OAuthException(Response.CANNOT_AUTHENTICATE_USER, HttpResponseStatus.UNAUTHORIZED); //NOSONAR
            }
        }
        return accessToken;
    }

    protected String authenticateUser(String username, String password) throws IOException {
        UserAuthentication ua = new UserAuthentication();
        return ua.authenticate(username, password);
    }

    protected String getBasicAuthorizationClientId(HttpRequest req) {
        // extract Basic Authorization header
        String authHeader = req.getHeader(HttpHeaders.AUTHORIZATION);
        String clientId = null;
        if(authHeader != null && authHeader.contains(BASIC)) {
            String value = authHeader.replace(BASIC,"");
            Base64 decoder = new Base64();
            byte [] decodedBytes = decoder.decode(value);
            String decoded = new String(decodedBytes, Charset.forName("UTF-8"));
            //client_id:client_secret - should be changed by client password
            String [] str = decoded.split(":");
            if(str.length == 2) {
                String authClientId = str[0];
                String authClientSecret = str[1];
                //check valid - DB call
                if(db.validClient(authClientId, authClientSecret)) {
                    clientId = authClientId;
                }
            }
        }
        return clientId;
    }

    protected AuthCode findAuthCode(TokenRequest tokenRequest) {
       return db.findAuthCode(tokenRequest.getCode(), tokenRequest.getRedirectUri());
    }

    public AccessToken isValidToken(String token) {
        AccessToken accessToken = db.findAccessToken(token);
        if(accessToken != null) {
            if(accessToken.tokenExpired()) {
                db.updateAccessTokenValidStatus(accessToken.getToken(), false);
                return null;
            }
            return accessToken;
        }
        return null;
    }

    public String getApplicationName(String clientId) {
        String appName = null;
        ClientCredentials creds = db.findClientCredentials(clientId);
        if(creds != null) {
            appName = creds.getName();
        }
        return appName;
    }

    protected String generateCode() {
        return AuthCode.generate();
    }

    protected boolean isValidClientId(String clientId) {
        if(db.findClientCredentials(clientId) != null) {
             return true;
        }
        return false;
    }

    protected String getExpiresIn(String tokenGrantType) {
        if(TokenRequest.CLIENT_CREDENTIALS.equals(tokenGrantType)) {
            return String.valueOf(OAuthServer.getExpiresInClientCredentials());
        }
        if(TokenRequest.PASSWORD.equals(tokenGrantType)) {
            return String.valueOf(OAuthServer.getExpiresInPassword());
        } else {
            return String.valueOf(OAuthServer.getExpiresInPassword());
        }
    }

    public boolean revokeToken(HttpRequest req) throws OAuthException {
        String clientId = getBasicAuthorizationClientId(req);
        if(clientId == null){
            throw new OAuthException(Response.INVALID_CLIENT_ID, HttpResponseStatus.BAD_REQUEST);
        }

        String token = getAccessToken(req);
        AccessToken accessToken = db.findAccessToken(token);
        if(accessToken != null) {
            if(accessToken.tokenExpired()) {
                log.debug("access token {} is expired", token);
                return true;
            }
            if(clientId.equals(accessToken.getClientId())) {
                db.updateAccessTokenValidStatus(accessToken.getToken(), false);
                log.debug("access token {} set status invalid", token);
                return true;
            } else {
                log.debug("access token {} is not obtained for that clientId {}", token, clientId);
                return false;
            }
        }
        log.debug("access token {} not found", token);
        return false;
    }

    private String getAccessToken(HttpRequest req) {
        String content = req.getContent().toString(CharsetUtil.UTF_8);
        String token = null;
        try {
            JSONObject obj = new JSONObject(content);
            token = obj.getString("access_token");
        } catch (JSONException e) {
            log.error("cannot parse JSON, {}", content);
        }
        return token;
    }
}
