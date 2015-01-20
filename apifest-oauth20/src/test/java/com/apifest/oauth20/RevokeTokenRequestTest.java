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

import static org.mockito.BDDMockito.willReturn;
import static org.mockito.Mockito.mock;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.util.CharsetUtil;
import org.testng.annotations.Test;

/**
 * @author Rossitsa Borissova
 */
public class RevokeTokenRequestTest {

    @Test
    public void when_revoke_token_request_content_create_revoke_token_request_object() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String content = "{\"access_token\":\"9376e098e8190835a0b41d83355f92d66f425469\"," +
            "\"client_id\":\"203598599234220\"}";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        willReturn(buf).given(req).getContent();

        // WHEN
        RevokeTokenRequest revokeTokenReq = new RevokeTokenRequest(req);

        // THEN
        assertEquals(revokeTokenReq.getAccessToken(), "9376e098e8190835a0b41d83355f92d66f425469");
        assertEquals(revokeTokenReq.getClientId(), "203598599234220");
    }

    @Test
    public void when_access_token_missing_then_revoke_token_request_access_token_null() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String content = "{\"client_id\":\"203598599234220\"," +
            "\"client_secret\":\"bb635eb22c5b5ce3de06e31bb88be7ae\"}";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        willReturn(buf).given(req).getContent();

        // WHEN
        RevokeTokenRequest revokeTokenReq = new RevokeTokenRequest(req);

        // THEN
        assertNull(revokeTokenReq.getAccessToken());
        assertEquals(revokeTokenReq.getClientId(), "203598599234220");
    }


    @Test
    public void when_client_id_missing_then_revoke_token_request_client_id_null() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String content = "{\"access_token\":\"9376e098e8190835a0b41d83355f92d66f425469\"," +
            "\"client_secret\":\"bb635eb22c5b5ce3de06e31bb88be7ae\"}";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        willReturn(buf).given(req).getContent();

        // WHEN
        RevokeTokenRequest revokeTokenReq = new RevokeTokenRequest(req);

        // THEN
        assertEquals(revokeTokenReq.getAccessToken(), "9376e098e8190835a0b41d83355f92d66f425469");
        assertNull(revokeTokenReq.getClientId());
    }

    @Test
    public void when_accessToken_null_return_bad_request() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String content = "{\"client_id\":\"203598599234220\"," +
            "\"client_secret\":\"bb635eb22c5b5ce3de06e31bb88be7ae\"}";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        willReturn(buf).given(req).getContent();
        RevokeTokenRequest revokeTokenReq = new RevokeTokenRequest(req);

        // WHEN
        String errorMsg = null;
        HttpResponseStatus status = null;
        try {
            revokeTokenReq.checkMandatoryParams();
        } catch (OAuthException e){
            errorMsg = e.getMessage();
            status = e.getHttpStatus();
        }

        // THEN
        assertEquals(errorMsg, String.format(Response.MANDATORY_PARAM_MISSING, RevokeTokenRequest.ACCESS_TOKEN));
        assertEquals(status, HttpResponseStatus.BAD_REQUEST);
    }

    @Test
    public void when_accessToken_empty_return_bad_request() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String content = "{\"access_token\":\"\"," +
            "\"client_id\":\"203598599234220\",\"client_secret\":\"bb635eb22c5b5ce3de06e31bb88be7ae\"}";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        willReturn(buf).given(req).getContent();
        RevokeTokenRequest revokeTokenReq = new RevokeTokenRequest(req);

        // WHEN
        String errorMsg = null;
        HttpResponseStatus status = null;
        try {
            revokeTokenReq.checkMandatoryParams();
        } catch (OAuthException e){
            errorMsg = e.getMessage();
            status = e.getHttpStatus();
        }

        // THEN
        assertEquals(errorMsg, String.format(Response.MANDATORY_PARAM_MISSING, RevokeTokenRequest.ACCESS_TOKEN));
        assertEquals(status, HttpResponseStatus.BAD_REQUEST);
    }

    @Test
    public void when_clientId_null_return_bad_request() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String content = "{\"access_token\":\"9376e098e8190835a0b41d83355f92d66f425469\"," +
            "\"client_secret\":\"bb635eb22c5b5ce3de06e31bb88be7ae\"}";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        willReturn(buf).given(req).getContent();
        RevokeTokenRequest revokeTokenReq = new RevokeTokenRequest(req);

        // WHEN
        String errorMsg = null;
        HttpResponseStatus status = null;
        try {
            revokeTokenReq.checkMandatoryParams();
        } catch (OAuthException e){
            errorMsg = e.getMessage();
            status = e.getHttpStatus();
        }

        // THEN
        assertEquals(errorMsg, String.format(Response.MANDATORY_PARAM_MISSING, RevokeTokenRequest.CLIENT_ID));
        assertEquals(status, HttpResponseStatus.BAD_REQUEST);
    }

    @Test
    public void when_clientId_empty_return_bad_request() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String content = "{\"access_token\":\"9376e098e8190835a0b41d83355f92d66f425469\"," +
            "\"client_id\":\"\",\"client_secret\":\"bb635eb22c5b5ce3de06e31bb88be7ae\"}";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        willReturn(buf).given(req).getContent();
        RevokeTokenRequest revokeTokenReq = new RevokeTokenRequest(req);

        // WHEN
        String errorMsg = null;
        HttpResponseStatus status = null;
        try {
            revokeTokenReq.checkMandatoryParams();
        } catch (OAuthException e){
            errorMsg = e.getMessage();
            status = e.getHttpStatus();
        }

        // THEN
        assertEquals(errorMsg, String.format(Response.MANDATORY_PARAM_MISSING, RevokeTokenRequest.CLIENT_ID));
        assertEquals(status, HttpResponseStatus.BAD_REQUEST);
    }

    @Test
    public void when_invalid_JSON_return_revoke_request_with_null_values() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String content = "{\"access_token\":\"9376e098e8190835a0b41d83355f92d66f425469\"," +
            ",,,\"client_id\":\"203598599234220\"}";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        willReturn(buf).given(req).getContent();

        // WHEN
        RevokeTokenRequest revokeTokenReq = new RevokeTokenRequest(req);

        // THEN
        assertNull(revokeTokenReq.getAccessToken());
        assertNull(revokeTokenReq.getClientId());
    }
}
