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
import static org.mockito.BDDMockito.willReturn;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.util.CharsetUtil;
import org.slf4j.Logger;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * @author Rossitsa Borissova
 */
public class HttpRequestHandlerTest {

    HttpRequestHandler handler;
    Channel channel;

    @BeforeMethod
    public void setup() {
        handler = spy(new HttpRequestHandler());
        handler.log = mock(Logger.class);
        channel = mock(Channel.class);
        ChannelFuture future = mock(ChannelFuture.class);
        given(channel.write(anyObject())).willReturn(future);
        OAuthException.log = mock(Logger.class);
    }

    @Test
    public void when_register_invoke_issue_client_credentials() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        given(req.getUri()).willReturn("http://example.com/oauth20/register?app_name=TestDemoApp");
        AuthorizationServer auth = mock(AuthorizationServer.class);
        ClientCredentials creds = new ClientCredentials("TestDemoApp", "basic");
        given(auth.issueClientCredentials(req)).willReturn(creds);
        handler.auth = auth;

        // WHEN
        HttpResponse response = handler.handleRegister(req);

        // THEN
        verify(handler.auth).issueClientCredentials(req);
        String res = new String(response.getContent().array());
        assertTrue(res.contains("client_id"));
    }

    @Test
    public void when_register_and_OAuth_exception_occurs_return_error() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        given(req.getUri()).willReturn("http://example.com/oauth20/register?app_name=TestDemoApp&scope=basic");
        AuthorizationServer auth = mock(AuthorizationServer.class);
        willThrow(new OAuthException(Response.APPNAME_OR_SCOPE_IS_NULL, HttpResponseStatus.BAD_REQUEST))
            .given(auth).issueClientCredentials(req);
        handler.auth = auth;

        // WHEN
        HttpResponse response = handler.handleRegister(req);

        // THEN
        String res = new String(response.getContent().array());
        assertTrue(res.contains(Response.APPNAME_OR_SCOPE_IS_NULL));
    }

    @Test
    public void when_register_and_JSON_exception_occurs_return_error() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        AuthorizationServer auth = mock(AuthorizationServer.class);
        ClientCredentials creds = mock(ClientCredentials.class);
        willReturn(creds).given(auth).issueClientCredentials(req);
        handler.auth = auth;

        // WHEN
        HttpResponse response = handler.handleRegister(req);

        // THEN
        assertEquals(response.getContent().toString(CharsetUtil.UTF_8), Response.CANNOT_REGISTER_APP);
    }

    @Test
    public void when_OAuthException_return_response_with_exception_status() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        AuthorizationServer auth = mock(AuthorizationServer.class);
        OAuthException ex = new OAuthException(Response.APPNAME_OR_SCOPE_IS_NULL, HttpResponseStatus.BAD_REQUEST);
        willThrow(ex).given(auth).issueClientCredentials(req);
        handler.auth = auth;

        // WHEN
        HttpResponse response = handler.handleRegister(req);

        // THEN
        assertEquals(response.getStatus(), ex.getHttpStatus());
    }

    @Test
    public void when_revoke_token_return_revoked_true_message() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        AuthorizationServer auth = mock(AuthorizationServer.class);
        willReturn(true).given(auth).revokeToken(req);
        handler.auth = auth;

        // WHEN
        HttpResponse response = handler.handleTokenRevoke(req);

        // THEN
        assertEquals(new String(response.getContent().array()), "{\"revoked\":\"true\"}");
    }

    @Test
    public void when_revoke_token_return_revoked_false_message() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        AuthorizationServer auth = mock(AuthorizationServer.class);
        willReturn(false).given(auth).revokeToken(req);
        handler.auth = auth;

        // WHEN
        HttpResponse response = handler.handleTokenRevoke(req);

        // THEN
        assertEquals(new String(response.getContent().array()), "{\"revoked\":\"false\"}");
    }

    @Test
    public void when_revoke_token_throws_exception_return_revoked_false_message() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        OAuthException.log = mock(Logger.class);
        AuthorizationServer auth = mock(AuthorizationServer.class);
        willThrow(new OAuthException("something wrong", HttpResponseStatus.BAD_REQUEST)).given(auth).revokeToken(req);
        handler.auth = auth;

        // WHEN
        HttpResponse response = handler.handleTokenRevoke(req);

        // THEN
        assertEquals(new String(response.getContent().array()), "{\"revoked\":\"false\"}");
    }

    @Test
    public void when_register_scope_invoke_scope_service() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        ScopeService scopeService = mock(ScopeService.class);
        willReturn(scopeService).given(handler).getScopeService();
        HttpResponse res = mock(HttpResponse.class);
        willReturn(res).given(scopeService).registerScope(req);

        // WHEN
        handler.handleRegisterScope(req);

        // THEN
        verify(scopeService).registerScope(req);
    }

    @Test
    public void when_get_scope_invoke_scope_service() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        ScopeService scopeService = mock(ScopeService.class);
        willReturn(scopeService).given(handler).getScopeService();
        HttpResponse res = mock(HttpResponse.class);
        willReturn(res).given(scopeService).getScopes(req);

        // WHEN
        handler.handleGetScopes(req);

        // THEN
        verify(scopeService).getScopes(req);
    }
}
