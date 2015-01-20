/*
 * Copyright 2014, ApiFest project
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

import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.util.CharsetUtil;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

/**
 * Represents request when POST to /oauth20/tokens/revoke.
 *
 * @author Rossitsa Borissova
 */
public class RevokeTokenRequest {

    protected static final String ACCESS_TOKEN = "access_token";
    protected static final String CLIENT_ID = "client_id";

    private String accessToken;
    private String clientId;

    public RevokeTokenRequest(HttpRequest request) {
        String content = request.getContent().toString(CharsetUtil.UTF_8);
        JsonParser parser = new JsonParser();
        try {
            JsonObject jsonObj= parser.parse(content).getAsJsonObject();
            this.accessToken = (jsonObj.get(ACCESS_TOKEN) != null) ? jsonObj.get(ACCESS_TOKEN).getAsString() : null;
            this.clientId = (jsonObj.get(CLIENT_ID) != null) ? jsonObj.get(CLIENT_ID).getAsString() : null;
        } catch (JsonSyntaxException e) {
            // do nothing
        }
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    protected void checkMandatoryParams() throws OAuthException {
        if (accessToken == null || accessToken.isEmpty()) {
            throw new OAuthException(String.format(Response.MANDATORY_PARAM_MISSING, ACCESS_TOKEN),
                    HttpResponseStatus.BAD_REQUEST);
        }
        if (clientId == null || clientId.isEmpty()) {
            throw new OAuthException(String.format(Response.MANDATORY_PARAM_MISSING, CLIENT_ID),
                    HttpResponseStatus.BAD_REQUEST);
        }
    }
}
