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

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.util.CharsetUtil;

/**
 * Represents token request.
 *
 * @author Rossitsa Borissova
 */
public class TokenRequest {

    public static final String AUTHORIZATION_CODE = "authorization_code";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String CLIENT_CREDENTIALS = "client_credentials";
    public static final String PASSWORD = "password";

    protected static final String GRANT_TYPE = "grant_type";
    protected static final String CODE = "code";
    protected static final String REDIRECT_URI = "redirect_uri";
    protected static final String CLIENT_ID = "client_id";
    protected static final String CLIENT_SECRET = "client_secret";
    protected static final String SCOPE = "scope";
    protected static final String USERNAME = "username";

    private String grantType;
    private String code;
    private String redirectUri;
    private String clientId;
    private String clientSecret;
    private String refreshToken;
    private String scope;
    private String username;
    private String password;

    private String userId;

    public TokenRequest(HttpRequest request) {
        String content = request.getContent().toString(CharsetUtil.UTF_8);
        List<NameValuePair> values = URLEncodedUtils.parse(content, Charset.forName("UTF-8"));
        Map<String, String> params = new HashMap<String, String>();
        for (NameValuePair pair : values) {
            params.put(pair.getName(), pair.getValue());
        }
        this.grantType = params.get(GRANT_TYPE);
        this.code = params.get(CODE);
        this.redirectUri = params.get(REDIRECT_URI);
        this.clientId = params.get(CLIENT_ID);
        this.clientSecret = params.get(CLIENT_SECRET);
        if (this.clientId == null && this.clientSecret == null) {
            String [] clientCredentials = AuthorizationServer.getBasicAuthorizationClientCredentials(request);
            this.clientId = clientCredentials [0];
            this.clientSecret = clientCredentials [1];
        }
        this.refreshToken = params.get(REFRESH_TOKEN);
        this.scope = params.get(SCOPE);
        this.username = params.get(USERNAME);
        this.password = params.get(PASSWORD);
    }

    public void validate() throws OAuthException {
        checkMandatoryParams();
        if (!grantType.equals(AUTHORIZATION_CODE) && !grantType.equals(REFRESH_TOKEN)
                && !grantType.equals(CLIENT_CREDENTIALS) && !grantType.equals(PASSWORD)
                && !grantType.equals(OAuthServer.getCustomGrantType())) {
            throw new OAuthException(Response.GRANT_TYPE_NOT_SUPPORTED,
                    HttpResponseStatus.BAD_REQUEST);
        }
        if (grantType.equals(AUTHORIZATION_CODE)) {
            if (code == null) {
                throw new OAuthException(String.format(Response.MANDATORY_PARAM_MISSING, CODE),
                        HttpResponseStatus.BAD_REQUEST);
            }
            if (redirectUri == null) {
                throw new OAuthException(String.format(Response.MANDATORY_PARAM_MISSING,
                        REDIRECT_URI), HttpResponseStatus.BAD_REQUEST);
            }
        }
        if (grantType.equals(REFRESH_TOKEN) && refreshToken == null) {
            throw new OAuthException(
                    String.format(Response.MANDATORY_PARAM_MISSING, REFRESH_TOKEN),
                    HttpResponseStatus.BAD_REQUEST);
        }
        if (grantType.equals(PASSWORD)) {
            if (username == null) {
                throw new OAuthException(String.format(Response.MANDATORY_PARAM_MISSING, USERNAME),
                        HttpResponseStatus.BAD_REQUEST);
            }
            if (password == null) {
                throw new OAuthException(String.format(Response.MANDATORY_PARAM_MISSING, PASSWORD),
                        HttpResponseStatus.BAD_REQUEST);
            }
        }
    }

    protected void checkMandatoryParams() throws OAuthException {
        if (clientId == null || clientId.isEmpty()) {
            throw new OAuthException(String.format(Response.MANDATORY_PARAM_MISSING, CLIENT_ID),
                    HttpResponseStatus.BAD_REQUEST);
        }
        if (clientSecret == null || clientSecret.isEmpty()) {
            throw new OAuthException(String.format(Response.MANDATORY_PARAM_MISSING, CLIENT_SECRET),
                    HttpResponseStatus.BAD_REQUEST);
        }
        if (grantType == null || grantType.isEmpty()) {
            throw new OAuthException(String.format(Response.MANDATORY_PARAM_MISSING, GRANT_TYPE),
                    HttpResponseStatus.BAD_REQUEST);
        }
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getGrantType() {
        return grantType;
    }

    public String getCode() {
        return code;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getClientId() {
        return clientId;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getScope() {
        return scope;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getClientSecret() {
        return clientSecret;
    }

}
