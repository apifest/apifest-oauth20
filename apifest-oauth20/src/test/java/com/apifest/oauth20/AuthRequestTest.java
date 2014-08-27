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

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import org.jboss.netty.handler.codec.http.HttpRequest;
import org.slf4j.Logger;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * @author Rossitsa Borissova
 */
public class AuthRequestTest {

    @BeforeMethod
    public void setup() {
        OAuthException.log = mock(Logger.class);
    }

    @Test
    public void when_uri_not_valid_return_false() {
        // WHEN
        boolean ok = AuthRequest.isValidURI("htp://example.com");

        // THEN
        assertFalse(ok);
    }

    @Test
    public void when_uri_valid_return_true() {
        // WHEN
        boolean ok = AuthRequest.isValidURI("http://example.com");

        // THEN
        assertTrue(ok);
    }

    @Test
    public void given_request_initialize_fields() throws Exception {
        // GIVEN
        HttpRequest request = mock(HttpRequest.class);
        String responseType = "code";
        String clientId = "763273054098803";
        String state = "xyz";
        String scope = "basic";
        given(request.getUri()).willReturn(
                "http://example.com/authorize?response_type=" + responseType + "&client_id="
                        + clientId + "&state=" + state
                        + "&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom&scope=" + scope);

        // WHEN
        AuthRequest authReq = new AuthRequest(request);

        // THEN
        assertEquals(authReq.getResponseType(), "code");
        assertEquals(authReq.getClientId(), clientId);
        assertEquals(authReq.getState(), state);
        assertEquals(authReq.getRedirectUri(), "https://client.example.com");
        assertEquals(authReq.getScope(), scope);
    }

    @Test
    public void when_validate_and_response_type_unsupported_return_errror() throws Exception {
        // GIVEN
        HttpRequest request = mock(HttpRequest.class);
        String responseType = "unsupported";
        String clientId = "763273054098803";
        String state = "xyz";
        String scope = "basic";
        given(request.getUri()).willReturn(
                "http://example.com/authorize?response_type=" + responseType + "&client_id="
                        + clientId + "&state=" + state
                        + "&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom&scope=" + scope);

        AuthRequest authReq = spy(new AuthRequest(request));

        // WHEN
        String errorMsg = null;
        try {
            authReq.validate();
        } catch (OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg, Response.RESPONSE_TYPE_NOT_SUPPORTED);
    }

    @Test
    public void when_validate_and_redirect_uri_invalid_return_errror() throws Exception {
        // GIVEN
        HttpRequest request = mock(HttpRequest.class);
        String responseType = "code";
        String clientId = "763273054098803";
        String state = "xyz";
        String scope = "basic";
        given(request.getUri()).willReturn(
                "http://example.com/authorize?response_type=" + responseType + "&client_id="
                        + clientId + "&state=" + state
                        + "&redirect_uri=%3A%2F%2Fclient%2Eexample%2Ecom&scope=" + scope);

        AuthRequest authReq = spy(new AuthRequest(request));

        // WHEN
        String errorMsg = null;
        try {
            authReq.validate();
        } catch (OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg, Response.INVALID_REDIRECT_URI);
    }
}
