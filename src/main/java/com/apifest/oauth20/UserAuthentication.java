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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;

import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class responsible for user authentication. Example user authentication, MUST be changed.
 *
 * @author Rossitsa Borissova
 */
public class UserAuthentication {

    private Logger log = LoggerFactory.getLogger(UserAuthentication.class);

    /**
     * Authenticates user by username and password.
     *
     * @param username
     * @param password
     * @return unique id of the user
     * @throws IOException
     */
    public String authenticate(String username, String password) throws IOException {
        String userId = null;
        HttpPost post = new HttpPost(OAuthServer.getUserAuthEndpoint());
        post.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
        HttpClient httpClient = new DefaultHttpClient();
        HttpResponse response;
        JSONObject json = new JSONObject();
        try {
            json.put("username", username);
            json.put("password", password);
            post.setEntity(new StringEntity(json.toString(), "UTF-8"));
            response = httpClient.execute(post);
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                String res = readResponse(response);
                log.debug("json response: " + res);
                JSONObject jsonResponse = new JSONObject(res);
                userId = jsonResponse.getString(OAuthServer.getUserIdJsonName());
                log.debug("user_id: " + userId);
            }
        } catch (JSONException e) {
            log.error("Cannot get user id", e);
        } catch (UnsupportedEncodingException e) {
            log.error("Cannot post to authenticate user", e);
        }
        return userId;
    }

    protected String readResponse(HttpResponse response) throws IOException {
        InputStream in = null;
        ByteArrayOutputStream out = null;
        String result = null;
        try {
            in = response.getEntity().getContent();
            out = new ByteArrayOutputStream();
            byte[] b = new byte[1024];
            while ((in.read(b) != -1)) {
                out.write(b);
            }
            out.flush();
            result = out.toString("UTF-8").trim();
        } finally {
            if (in != null) {
                in.close();
            }
            if (out != null) {
                out.close();
            }
        }
        return result;
    }

}
