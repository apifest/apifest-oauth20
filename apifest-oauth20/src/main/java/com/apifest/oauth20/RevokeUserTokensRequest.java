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
 * Represents request when DELETE to /oauth20/tokens.
 *
 * @author Ivan Zhivkov
 */
public class RevokeUserTokensRequest {

    protected static final String USER_ID = "user_id";

    private String userId;

    public RevokeUserTokensRequest(HttpRequest request) {
        String content = request.getContent().toString(CharsetUtil.UTF_8);
        JsonParser parser = new JsonParser();
        try {
            JsonObject jsonObj= parser.parse(content).getAsJsonObject();
            this.userId = (jsonObj.get(USER_ID) != null) ? jsonObj.get(USER_ID).getAsString() : null;
        } catch (JsonSyntaxException e) {
            // do nothing
        }
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    protected void checkMandatoryParams() throws OAuthException {
        if (userId == null || userId.isEmpty()) {
            throw new OAuthException(String.format(Response.MANDATORY_PARAM_MISSING, USER_ID),
                    HttpResponseStatus.BAD_REQUEST);
        }
    }
}
