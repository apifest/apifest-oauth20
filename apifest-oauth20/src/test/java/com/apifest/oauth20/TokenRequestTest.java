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
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.handler.codec.http.DefaultHttpHeaders;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.util.CharsetUtil;
import org.slf4j.Logger;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;


/**
 * @author Rossitsa Borissova
 */
public class TokenRequestTest {

    HttpRequest req;

    String clientId = "203598599234220";
    String clientSecret = "105ef93e7bb386da3a23c32e8563434fad005fd0a6a88315fcdf946aa761c838";

    @BeforeMethod
    public void setup() {
        req = mock(HttpRequest.class);
        OAuthException.log = mock(Logger.class);
    }

    @Test
    public void when_grant_type_is_missing_throws_exception() throws Exception {
        // GIVEN
        String content = "redirect_uri=example.com" + "&code=not_valid_code" + "&client_id=" + clientId + "&client_secret=" + clientSecret;
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        given(req.getContent()).willReturn(buf);
        TokenRequest tokenReq = new TokenRequest(req);

        // WHEN
        String errorMsg = null;
        try {
            tokenReq.validate();
        } catch (OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg, String.format(Response.MANDATORY_PARAM_MISSING, TokenRequest.GRANT_TYPE));
    }

    @Test
    public void when_grant_type_not_supported_throws_exception() throws Exception {
        // GIVEN
        String content = "redirect_uri=example.com"
                + "&grant_type=not_supported&code=not_valid_code" + "&client_id=" + clientId + "&client_secret=" + clientSecret;
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        given(req.getContent()).willReturn(buf);
        TokenRequest tokenReq = new TokenRequest(req);

        // WHEN
        String errorMsg = null;
        try {
            tokenReq.validate();
        } catch (OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg, Response.GRANT_TYPE_NOT_SUPPORTED);
    }

    @Test
    public void when_auth_code_is_missing_throws_exception() throws Exception {
        // GIVEN
        String content = "grant_type=" + TokenRequest.AUTHORIZATION_CODE
                + "&redirect_uri=example.com" + "&client_id=" + clientId + "&client_secret=" + clientSecret;
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        given(req.getContent()).willReturn(buf);
        TokenRequest tokenReq = new TokenRequest(req);

        // WHEN
        String errorMsg = null;
        try {
            tokenReq.validate();
        } catch (OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg, String.format(Response.MANDATORY_PARAM_MISSING, TokenRequest.CODE));
    }

    @Test
    public void when_redirect_uri_is_missing_throws_exception() throws Exception {
        // GIVEN
        String content = "grant_type=" + TokenRequest.AUTHORIZATION_CODE + "&code=valid_code&client_id=" + clientId + "&client_secret=" + clientSecret;
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        given(req.getContent()).willReturn(buf);

        TokenRequest tokenReq = new TokenRequest(req);


        // WHEN
        String errorMsg = null;
        try {
            tokenReq.validate();
        } catch (OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg, String.format(Response.MANDATORY_PARAM_MISSING, TokenRequest.REDIRECT_URI));
    }

    @Test
    public void when_client_id_is_missing_throws_exception() throws Exception {
        // GIVEN
        String content = "grant_type=" + TokenRequest.AUTHORIZATION_CODE
                + "&code=valid_code&redirect_uri=example.com" + "&client_secret=" + clientSecret;
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        given(req.getContent()).willReturn(buf);
        TokenRequest tokenReq = new TokenRequest(req);

        // WHEN
        String errorMsg = null;
        try {
            tokenReq.validate();
        } catch (OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg, String.format(Response.MANDATORY_PARAM_MISSING, TokenRequest.CLIENT_ID));
    }

    @Test
    public void when_all_mandatory_params_present_do_not_throw_exception() throws Exception {
        // GIVEN
        String content = "grant_type=" + TokenRequest.AUTHORIZATION_CODE
                + "&code=valid_code&redirect_uri=example.com&client_id=" + clientId + "&client_secret=" + clientSecret;
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        given(req.getContent()).willReturn(buf);
        TokenRequest tokenReq = new TokenRequest(req);

        // WHEN
        tokenReq.validate();
    }

    @Test
    public void when_grant_type_refresh_token_and_no_refresh_token_return_error() throws Exception {
        // GIVEN
        String content = "grant_type=" + TokenRequest.REFRESH_TOKEN + "&client_id=" + clientId + "&client_secret=" + clientSecret;
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        given(req.getContent()).willReturn(buf);
        TokenRequest tokenReq = new TokenRequest(req);

        // WHEN
        String errorMsg = null;
        try {
            tokenReq.validate();
        } catch (OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg,
                String.format(Response.MANDATORY_PARAM_MISSING, TokenRequest.REFRESH_TOKEN));
    }

    @Test
    public void when_grant_type_password_and_no_username_return_error() throws Exception {
        // GIVEN
        String content = "grant_type=" + TokenRequest.PASSWORD + "&password=pd1&wyfr&client_id=" + clientId + "&client_secret=" + clientSecret;
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        given(req.getContent()).willReturn(buf);
        TokenRequest tokenReq = new TokenRequest(req);

        // WHEN
        String errorMsg = null;
        try {
            tokenReq.validate();
        } catch (OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg,
                String.format(Response.MANDATORY_PARAM_MISSING, TokenRequest.USERNAME));
    }

    @Test
    public void when_grant_type_password_and_no_password_return_error() throws Exception {
        // GIVEN
        String content = "grant_type=" + TokenRequest.PASSWORD + "&username=rossi&client_id=" + clientId + "&client_secret=" + clientSecret;
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        given(req.getContent()).willReturn(buf);
        TokenRequest tokenReq = new TokenRequest(req);

        // WHEN
        String errorMsg = null;
        try {
            tokenReq.validate();
        } catch (OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg,
                String.format(Response.MANDATORY_PARAM_MISSING, TokenRequest.PASSWORD));
    }

    @Test
    public void when_clientId_empty_check_mandatory_params_throws_exception() throws Exception {
        // GIVEN
        String clientId = "";
        String content = "grant_type=" + TokenRequest.PASSWORD + "&username=rossi&client_id=" + clientId + "&client_secret=" + clientSecret;
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        given(req.getContent()).willReturn(buf);
        TokenRequest tokenReq = new TokenRequest(req);

        // WHEN
        String errorMsg = null;
        try {
            tokenReq.checkMandatoryParams();
        } catch (OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg, String.format(Response.MANDATORY_PARAM_MISSING, TokenRequest.CLIENT_ID));
    }

    @Test
    public void when_grantType_empty_check_mandatory_params_throws_exception() throws Exception {
        // GIVEN
        String content = "grant_type=" + "" +"&username=rossi&client_id=" + clientId + "&client_secret=" + clientSecret;
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        given(req.getContent()).willReturn(buf);
        TokenRequest tokenReq = new TokenRequest(req);

        // WHEN
        String errorMsg = null;
        try {
            tokenReq.checkMandatoryParams();
        } catch (OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg, String.format(Response.MANDATORY_PARAM_MISSING, TokenRequest.GRANT_TYPE));
    }

    @Test
    public void when_client_credentials_not_in_request_body_then_extract_them_from_Authorization_header() throws Exception {
        String content = "grant_type=password&username=rossi&password=secret";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        given(req.getContent()).willReturn(buf);
        // clientId:clientSecret, 203598599234220:105ef93e7bb386da3a23c32e8563434fad005fd0a6a88315fcdf946aa761c838
        String basicHeader = "Basic MjAzNTk4NTk5MjM0MjIwOjEwNWVmOTNlN2JiMzg2ZGEzYTIzYzMyZTg1NjM0MzRmYWQwMDVmZDBhNmE4ODMxNWZjZGY5NDZhYTc2MWM4Mzg=";
        HttpHeaders headers = new DefaultHttpHeaders();
        headers.set(HttpHeaders.Names.AUTHORIZATION, basicHeader);
        given(req.headers()).willReturn(headers);

        // WHEN
        TokenRequest tokenReq = new TokenRequest(req);

        // THEN
        assertEquals(tokenReq.getClientId(), clientId);
        assertEquals(tokenReq.getClientSecret(), clientSecret);
    }

    @Test
    public void when_client_credentials_not_in_request_body_and_no_Authorization_header_then_client_credentials_are_null() throws Exception {
        String content = "grant_type=password&username=rossi&password=secret";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        given(req.getContent()).willReturn(buf);
        HttpHeaders headers = new DefaultHttpHeaders();
        given(req.headers()).willReturn(headers);

        // WHEN
        TokenRequest tokenReq = new TokenRequest(req);

        // THEN
        assertNull(tokenReq.getClientId());
        assertNull(tokenReq.getClientSecret());
    }

    @Test
    public void when_client_credentials_not_in_request_body_and_invalid_Authorization_header_then_client_credentials_are_null() throws Exception {
        String content = "grant_type=password&username=rossi&password=secret";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        given(req.getContent()).willReturn(buf);
        String basicHeader = "Basic ";
        HttpHeaders headers = new DefaultHttpHeaders();
        headers.set(HttpHeaders.Names.AUTHORIZATION, basicHeader);
        given(req.headers()).willReturn(headers);

        // WHEN
        TokenRequest tokenReq = new TokenRequest(req);

        // THEN
        assertNull(tokenReq.getClientId());
        assertNull(tokenReq.getClientSecret());
    }
}
