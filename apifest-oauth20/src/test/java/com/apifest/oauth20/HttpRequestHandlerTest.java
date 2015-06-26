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
import static org.mockito.BDDMockito.willDoNothing;
import static org.mockito.BDDMockito.willReturn;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.handler.codec.http.DefaultHttpHeaders;
import org.jboss.netty.handler.codec.http.DefaultHttpRequest;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpMethod;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.HttpVersion;
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
        OAuthServer.log = mock(Logger.class);
        String path = getClass().getClassLoader().getResource("apifest-oauth-test.properties").getPath();
        System.setProperty("properties.file", path);
        OAuthServer.loadConfig();

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
        ClientCredentials creds = new ClientCredentials("TestDemoApp", "basic", "descr", "http://example.com", null);
        given(auth.issueClientCredentials(req)).willReturn(creds);
        handler.auth = auth;

        // WHEN
        HttpResponse response = handler.handleRegister(req);

        // THEN
        verify(handler.auth).issueClientCredentials(req);
        String res = response.getContent().toString(CharsetUtil.UTF_8);
        assertTrue(res.contains("client_id"));
    }

    @Test
    public void when_register_and_OAuth_exception_occurs_return_error() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        given(req.getUri()).willReturn(
                "http://example.com/oauth20/register?app_name=TestDemoApp&scope=basic");
        AuthorizationServer auth = mock(AuthorizationServer.class);
        willThrow(
                new OAuthException(Response.NAME_OR_SCOPE_OR_URI_IS_NULL,
                        HttpResponseStatus.BAD_REQUEST)).given(auth).issueClientCredentials(req);
        handler.auth = auth;

        // WHEN
        HttpResponse response = handler.handleRegister(req);

        // THEN
        String res = response.getContent().toString(CharsetUtil.UTF_8);
        assertTrue(res.contains(Response.NAME_OR_SCOPE_OR_URI_IS_NULL));
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
        assertEquals(response.getContent().toString(CharsetUtil.UTF_8),
                Response.CANNOT_REGISTER_APP);
    }

    @Test
    public void when_OAuthException_return_response_with_exception_status() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        AuthorizationServer auth = mock(AuthorizationServer.class);
        OAuthException ex = new OAuthException(Response.NAME_OR_SCOPE_OR_URI_IS_NULL,
                HttpResponseStatus.BAD_REQUEST);
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
        assertEquals(response.getContent().toString(CharsetUtil.UTF_8), "{\"revoked\":\"true\"}");
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
        assertEquals(response.getContent().toString(CharsetUtil.UTF_8), "{\"revoked\":\"false\"}");
    }

    @Test
    public void when_revoke_token_throws_exception_return_bad_request_message() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        OAuthException.log = mock(Logger.class);
        AuthorizationServer auth = mock(AuthorizationServer.class);
        String errorMsg = "something wrong";
        willThrow(new OAuthException(errorMsg, HttpResponseStatus.BAD_REQUEST))
                .given(auth).revokeToken(req);
        handler.auth = auth;

        // WHEN
        HttpResponse response = handler.handleTokenRevoke(req);

        // THEN
        assertEquals(response.getContent().toString(CharsetUtil.UTF_8), errorMsg);
        assertEquals(response.getStatus(), HttpResponseStatus.BAD_REQUEST);
    }

    @Test
    public void when_register_scope_invoke_scope_service() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        ScopeService scopeService = mock(ScopeService.class);
        willReturn(scopeService).given(handler).getScopeService();
        willReturn("OK").given(scopeService).registerScope(req);

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
        willReturn("basic extended").given(scopeService).getScopes(req);

        // WHEN
        handler.handleGetAllScopes(req);

        // THEN
        verify(scopeService).getScopes(req);
    }

    @Test
    public void when_PUT_scope_invoke_updateScope_method() throws Exception {
        // GIVEN
        ChannelHandlerContext ctx = mockChannelHandlerContext();

        MessageEvent event = mock(MessageEvent.class);
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.PUT, HttpRequestHandler.OAUTH_CLIENT_SCOPE_URI);
        willReturn(req).given(event).getMessage();
        willReturn(mock(HttpResponse.class)).given(handler).handleUpdateScope(req);

        // WHEN
        handler.messageReceived(ctx, event);

        // THEN
        verify(handler).handleUpdateScope(req);
    }

    @Test
    public void when_handle_updateScope_invoke_scope_service_update() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String scopeName = "scopeName";
        willReturn(HttpRequestHandler.OAUTH_CLIENT_SCOPE_URI + "/" + scopeName).given(req).getUri();
        ScopeService scopeService = mock(ScopeService.class);
        willReturn(scopeService).given(handler).getScopeService();
        willReturn("OK").given(scopeService).updateScope(req, scopeName);

        // WHEN
        handler.handleUpdateScope(req);

        // THEN
        verify(scopeService).updateScope(req, scopeName);
    }

    @Test
    public void when_POST_scope_invoke_handleRegisterScope_method() throws Exception {
        // GIVEN
        ChannelHandlerContext ctx = mockChannelHandlerContext();

        MessageEvent event = mock(MessageEvent.class);
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, HttpRequestHandler.OAUTH_CLIENT_SCOPE_URI);
        willReturn(req).given(event).getMessage();
        willReturn(mock(HttpResponse.class)).given(handler).handleRegisterScope(req);

        // WHEN
        handler.messageReceived(ctx, event);

        // THEN
        verify(handler).handleRegisterScope(req);
    }

    @Test
    public void when_GET_scope_invoke_handleGetScopes_method() throws Exception {
        // GIVEN
        ChannelHandlerContext ctx = mockChannelHandlerContext();

        MessageEvent event = mock(MessageEvent.class);
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, HttpRequestHandler.OAUTH_CLIENT_SCOPE_URI);
        willReturn(req).given(event).getMessage();
        willReturn(mock(HttpResponse.class)).given(handler).handleGetAllScopes(req);

        // WHEN
        handler.messageReceived(ctx, event);

        // THEN
        verify(handler).handleGetAllScopes(req);
    }

    @Test
    public void when_GET_application_with_clientId_invoke_handleGetClientApplication() throws Exception {
        // GIVEN
        ChannelHandlerContext ctx = mockChannelHandlerContext();
        MessageEvent event = mock(MessageEvent.class);
        String uri = HttpRequestHandler.APPLICATION_URI + "/218900b6c8d973881cf4185ecf2c6aba";
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, uri);
        willReturn(req).given(event).getMessage();
        willReturn(mock(HttpResponse.class)).given(handler).handleGetClientApplication(req);

        // WHEN
        handler.messageReceived(ctx, event);

        // THEN
        verify(handler).handleGetClientApplication(req);
    }

    @Test
    public void when_GET_application_with_clientId_invoke_get_application_with_client_id() throws Exception {
        // GIVEN
        String uri = HttpRequestHandler.APPLICATION_URI + "/218900b6c8d973881cf4185ecf2c6aba";
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, uri);
        AuthorizationServer auth = mock(AuthorizationServer.class);
        ApplicationInfo info = new ApplicationInfo();
        willReturn(info).given(auth).getApplicationInfo("218900b6c8d973881cf4185ecf2c6aba");
        handler.auth = auth;

        // WHEN
        handler.handleGetClientApplication(req);

        // THEN
        verify(handler.auth).getApplicationInfo("218900b6c8d973881cf4185ecf2c6aba");
    }

    @Test
    public void when_PUT_applications_invoke_handleUpdateClientApp() throws Exception {
        // GIVEN
        ChannelHandlerContext ctx = mockChannelHandlerContext();

        MessageEvent event = mock(MessageEvent.class);
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.PUT, HttpRequestHandler.APPLICATION_URI);
        willReturn(req).given(event).getMessage();
        willReturn(mock(HttpResponse.class)).given(handler).handleUpdateClientApplication(req);

        // WHEN
        handler.messageReceived(ctx, event);

        // THEN
        verify(handler).handleUpdateClientApplication(req);
    }

    @Test
    public void when_POST_applications_invoke_handleRegister() throws Exception {
        // GIVEN
        ChannelHandlerContext ctx = mockChannelHandlerContext();

        MessageEvent event = mock(MessageEvent.class);
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, HttpRequestHandler.APPLICATION_URI);
        willReturn(req).given(event).getMessage();
        willReturn(mock(HttpResponse.class)).given(handler).handleRegister(req);

        // WHEN
        handler.messageReceived(ctx, event);

        // THEN
        verify(handler).handleRegister(req);
    }

    @Test
    public void when_GET_applications_invoke_handleGetAllClientApplications() throws Exception {
        // GIVEN
        ChannelHandlerContext ctx = mockChannelHandlerContext();

        MessageEvent event = mock(MessageEvent.class);
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, HttpRequestHandler.APPLICATION_URI);
        willReturn(req).given(event).getMessage();
        willReturn(mock(HttpResponse.class)).given(handler).handleGetAllClientApplications(req);

        // WHEN
        handler.messageReceived(ctx, event);

        // THEN
        verify(handler).handleGetAllClientApplications(req);
    }

    @Test
    public void when_GET_applications_with_active_status_query_params_and_no_active_app_return_empty_list() throws Exception {
        // GIVEN
        String uri = HttpRequestHandler.APPLICATION_URI + "?status=" + ClientCredentials.ACTIVE_STATUS;
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, uri);
        ApplicationInfo app = mock(ApplicationInfo.class);
        willReturn(ClientCredentials.INACTIVE_STATUS).given(app).getStatus();
        List<ApplicationInfo> apps = new ArrayList<ApplicationInfo>();
        apps.add(app);
        MockDBManagerFactory.install();
        willReturn(apps).given(DBManagerFactory.getInstance()).getAllApplications();

        // WHEN
        HttpResponse response = handler.handleGetAllClientApplications(req);

        // THEN
        verify(handler).filterClientApps(req, apps);
        assertEquals(response.getContent().toString(CharsetUtil.UTF_8), "[]");
    }

    @Test
    public void when_GET_applications_with_active_status_query_params_return_client_apps_with_active_status() throws Exception {
        // GIVEN
        String uri = HttpRequestHandler.APPLICATION_URI + "?status=" + ClientCredentials.ACTIVE_STATUS;
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, uri);
        ApplicationInfo app = new ApplicationInfo();
        app.setStatus(ClientCredentials.ACTIVE_STATUS);
        app.setId("b9db6d84dc98a895035e68f972e30503d3c724c8");
        List<ApplicationInfo> apps = new ArrayList<ApplicationInfo>();
        apps.add(app);
        MockDBManagerFactory.install();
        willReturn(apps).given(DBManagerFactory.getInstance()).getAllApplications();

        // WHEN
        HttpResponse response = handler.handleGetAllClientApplications(req);

        // THEN
        verify(handler).filterClientApps(req, apps);
        assertEquals(response.getContent().toString(CharsetUtil.UTF_8), "[{\"client_id\":\"b9db6d84dc98a895035e68f972e30503d3c724c8\",\"status\":1}]");
    }

    @Test
    public void when_GET_applications_with_not_valid_status_query_params_return_all_client_apps() throws Exception {
        // GIVEN
        String uri = HttpRequestHandler.APPLICATION_URI + "?status=some";
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, uri);
        ApplicationInfo app = new ApplicationInfo();
        app.setStatus(ClientCredentials.ACTIVE_STATUS);
        app.setId("b9db6d84dc98a895035e68f972e30503d3c724c8");
        List<ApplicationInfo> apps = new ArrayList<ApplicationInfo>();
        apps.add(app);
        MockDBManagerFactory.install();
        willReturn(apps).given(DBManagerFactory.getInstance()).getAllApplications();

        // WHEN
        HttpResponse response = handler.handleGetAllClientApplications(req);

        // THEN
        verify(handler).filterClientApps(req, apps);
        assertEquals(response.getContent().toString(CharsetUtil.UTF_8), "[{\"client_id\":\"b9db6d84dc98a895035e68f972e30503d3c724c8\",\"status\":1}]");
    }

    @Test
    public void when_GET_applications_with_empty_status_query_params_return_all_client_apps() throws Exception {
        // GIVEN
        String uri = HttpRequestHandler.APPLICATION_URI + "?status=";
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, uri);
        ApplicationInfo app = new ApplicationInfo();
        app.setStatus(ClientCredentials.ACTIVE_STATUS);
        List<ApplicationInfo> apps = new ArrayList<ApplicationInfo>();
        apps.add(app);
        MockDBManagerFactory.install();
        willReturn(apps).given(DBManagerFactory.getInstance()).getAllApplications();

        // WHEN
        HttpResponse response = handler.handleGetAllClientApplications(req);

        // THEN
        verify(handler).filterClientApps(req, apps);
        assertEquals(response.getContent().toString(CharsetUtil.UTF_8), "[{\"status\":1}]");
    }


    @Test
    public void when_uri_does_not_match_OAUTH_SCOPE_DELETE_PATTERN_return_not_found() throws Exception {
        // GIVEN
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.DELETE, HttpRequestHandler.APPLICATION_URI);
        req.setUri(HttpRequestHandler.OAUTH_CLIENT_SCOPE_URI + "/non@ValidScope");

        // WHEN
        HttpResponse response = handler.handleDeleteScope(req);

        // THEN
        assertEquals(response.getStatus(), HttpResponseStatus.NOT_FOUND);
    }

    @Test
    public void when_uri_match_OAUTH_SCOPE_DELETE_PATTERN_delete_scope() throws Exception {
        // GIVEN
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.DELETE, HttpRequestHandler.APPLICATION_URI);
        req.setUri(HttpRequestHandler.OAUTH_CLIENT_SCOPE_URI + "/validScope");
        //getScopeService
        ScopeService scopeService = mock(ScopeService.class);
        willReturn(ScopeService.SCOPE_STORED_OK_MESSAGE).given(scopeService).deleteScope("validScope");
        willReturn(scopeService).given(handler).getScopeService();

        // WHEN
        HttpResponse response = handler.handleDeleteScope(req);

        // THEN
        assertEquals(response.getStatus(), HttpResponseStatus.OK);
        assertEquals(response.getContent().toString(CharsetUtil.UTF_8), ScopeService.SCOPE_STORED_OK_MESSAGE);
    }

    @Test
    public void when_delete_scope_NOK_return_200_with_NOK_message() throws Exception {
        // GIVEN
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.DELETE, HttpRequestHandler.APPLICATION_URI);
        req.setUri(HttpRequestHandler.OAUTH_CLIENT_SCOPE_URI + "/validScope");
        //getScopeService
        ScopeService scopeService = mock(ScopeService.class);
        willReturn(ScopeService.SCOPE_UPDATED_NOK_MESSAGE).given(scopeService).deleteScope("validScope");
        willReturn(scopeService).given(handler).getScopeService();

        // WHEN
        HttpResponse response = handler.handleDeleteScope(req);

        // THEN
        assertEquals(response.getStatus(), HttpResponseStatus.OK);
        assertEquals(response.getContent().toString(CharsetUtil.UTF_8), ScopeService.SCOPE_UPDATED_NOK_MESSAGE);
    }

    @Test
    public void when_delete_scope_throws_exception_return_400_http_status() throws Exception {
        // GIVEN
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.DELETE, HttpRequestHandler.APPLICATION_URI);
        req.setUri(HttpRequestHandler.OAUTH_CLIENT_SCOPE_URI + "/validScope");
        //getScopeService
        ScopeService scopeService = mock(ScopeService.class);
        willThrow(new OAuthException(ScopeService.SCOPE_NOT_EXIST, HttpResponseStatus.BAD_REQUEST)).given(scopeService).deleteScope("validScope");
        willReturn(scopeService).given(handler).getScopeService();

        // WHEN
        HttpResponse response = handler.handleDeleteScope(req);

        // THEN
        assertEquals(response.getStatus(), HttpResponseStatus.BAD_REQUEST);
        assertEquals(response.getContent().toString(CharsetUtil.UTF_8), ScopeService.SCOPE_NOT_EXIST);
    }

    @Test
    public void when_DELETE_scope_invoke_handleDeleteScope() throws Exception {
        // GIVEN
        ChannelHandlerContext ctx = mockChannelHandlerContext();

        MessageEvent event = mock(MessageEvent.class);
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.DELETE, HttpRequestHandler.OAUTH_CLIENT_SCOPE_URI + "/scope");
        willReturn(req).given(event).getMessage();
        willReturn(mock(HttpResponse.class)).given(handler).handleDeleteScope(req);

        // WHEN
        handler.messageReceived(ctx, event);

        // THEN
        verify(handler).handleDeleteScope(req);
    }

    @Test
    public void when_oauth20_delete_contains_scope_extract_scope_name() throws Exception {
        // GIVEN
        String scopeName = "my-super-scope";
        String uri = HttpRequestHandler.OAUTH_CLIENT_SCOPE_URI + "/" + scopeName;
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.DELETE, uri);
        ScopeService scopeService = mock(ScopeService.class);
        willReturn("OK").given(scopeService).deleteScope(scopeName);
        willReturn(scopeService).given(handler).getScopeService();

        // WHEN
        handler.handleDeleteScope(req);

        // THEN
        verify(scopeService).deleteScope(scopeName);
    }

    @Test
    public void when_oauth20_delete_contains_invalid_scope_return_not_found_response() throws Exception {
        // GIVEN
        String scopeName = "my-super-scope invalid";
        String uri = HttpRequestHandler.OAUTH_CLIENT_SCOPE_URI + "/" + scopeName;
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.DELETE, uri);
        ScopeService scopeService = mock(ScopeService.class);
        willReturn("OK").given(scopeService).deleteScope(scopeName);
        willReturn(scopeService).given(handler).getScopeService();

        // WHEN
        HttpResponse response = handler.handleDeleteScope(req);

        // THEN
        verify(scopeService, times(0)).deleteScope(scopeName);
        assertEquals(response.getStatus(), HttpResponseStatus.NOT_FOUND);
    }

    @Test
    public void when_token_is_null_do_not_try_to_validate_it() throws Exception {
        // GIVEN
        String uri = HttpRequestHandler.ACCESS_TOKEN_VALIDATE_URI;
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, uri);
        AuthorizationServer auth = mock(AuthorizationServer.class);
        handler.auth = auth;

        // WHEN
        HttpResponse response = handler.handleTokenValidate(req);

        // THEN
        verify(handler.auth, times(0)).isValidToken(anyString());
        assertEquals(response.getStatus(), HttpResponseStatus.BAD_REQUEST);
    }

    @Test
    public void when_token_is_empty_do_not_try_to_validate_it() throws Exception {
        // GIVEN
        String uri = HttpRequestHandler.ACCESS_TOKEN_VALIDATE_URI + "?token=";
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, uri);
        AuthorizationServer auth = mock(AuthorizationServer.class);
        handler.auth = auth;

        // WHEN
        HttpResponse response = handler.handleTokenValidate(req);

        // THEN
        verify(handler.auth, times(0)).isValidToken(anyString());
        assertEquals(response.getStatus(), HttpResponseStatus.BAD_REQUEST);
    }

    @Test
    public void when_handleGetClientApplication_with_non_existing_clientId_return_not_found_status() throws Exception {
        // GIVEN
        String clientId = "acf627defb833";
        String uri = HttpRequestHandler.APPLICATION_URI + "/" + clientId;
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, uri);
        AuthorizationServer auth = mock(AuthorizationServer.class);
        willReturn(null).given(auth).getApplicationInfo(clientId);
        handler.auth = auth;

        // WHEN
        HttpResponse response = handler.handleGetClientApplication(req);

        // THEN
        assertEquals(response.getStatus(), HttpResponseStatus.NOT_FOUND);
        assertEquals(response.getContent().toString(CharsetUtil.UTF_8), Response.CLIENT_APP_NOT_EXIST);
    }

    @Test
    public void when_content_type_is_not_application_form_urlencoded_on_post_tokens_return_400_and_unsupported_metida_type() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        HttpHeaders headers = new DefaultHttpHeaders();
        headers.add(HttpHeaders.Names.CONTENT_TYPE, "application/json");
        willReturn(headers).given(req).headers();

        // WHEN
        HttpResponse response = handler.handleToken(req);

        // THEN
        assertEquals(response.getStatus(), HttpResponseStatus.BAD_REQUEST);
        assertEquals(response.getContent().toString(CharsetUtil.UTF_8), Response.UNSUPPORTED_MEDIA_TYPE);
    }

    @Test
    public void when_revoke_token_and_oauth_exception_return_error_response() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        AuthorizationServer auth = mock(AuthorizationServer.class);
        handler.auth = auth;
        willThrow(new OAuthException(Response.INVALID_CLIENT_CREDENTIALS, HttpResponseStatus.BAD_REQUEST))
            .given(handler.auth).revokeToken(req);

        // WHEN
        HttpResponse response = handler.handleTokenRevoke(req);

        // THEN
        assertEquals(response.getContent().toString(CharsetUtil.UTF_8), Response.INVALID_CLIENT_CREDENTIALS);
        assertEquals(response.getStatus(), HttpResponseStatus.BAD_REQUEST);
    }

    @Test
    public void when_get_tokens_request_invoke_handleGetTokens_method() throws Exception {
        // GIVEN
        ChannelHandlerContext ctx = mockChannelHandlerContext();

        MessageEvent event = mock(MessageEvent.class);
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, HttpRequestHandler.ACCESS_TOKEN_URI);
        willReturn(req).given(event).getMessage();
        willReturn(mock(HttpResponse.class)).given(handler).handleGetAccessTokens(req);

        // WHEN
        handler.messageReceived(ctx, event);

        // THEN
        verify(handler).handleGetAccessTokens(req);
    }

    @Test
    public void when_get_tokens_and_client_id_is_null_return_missing_param_client_id() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        willReturn(HttpRequestHandler.ACCESS_TOKEN_URI + "?user_id=12343").given(req).getUri();

        // WHEN
        HttpResponse response = handler.handleGetAccessTokens(req);

        // THEN
        assertEquals(response.getContent().toString(CharsetUtil.UTF_8), String.format(Response.MANDATORY_PARAM_MISSING, "client_id"));
    }

    @Test
    public void when_get_tokens_and_client_id_is_empty_return_missing_param_client_id() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        willReturn(HttpRequestHandler.ACCESS_TOKEN_URI + "?user_id=12343&client_id=").given(req).getUri();

        // WHEN
        HttpResponse response = handler.handleGetAccessTokens(req);

        // THEN
        assertEquals(response.getContent().toString(CharsetUtil.UTF_8), String.format(Response.MANDATORY_PARAM_MISSING, "client_id"));
    }

    @Test
    public void when_get_tokens_and_user_id_is_null_return_missing_param_user_id() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        willReturn(HttpRequestHandler.ACCESS_TOKEN_URI + "?client_id=218900b6c8d973881cf4185ecf").given(req).getUri();

        // WHEN
        HttpResponse response = handler.handleGetAccessTokens(req);

        // THEN
        assertEquals(response.getContent().toString(CharsetUtil.UTF_8), String.format(Response.MANDATORY_PARAM_MISSING, "user_id"));
    }

    @Test
    public void when_get_tokens_and_user_id_is_empty_return_missing_param_user_id() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        willReturn(HttpRequestHandler.ACCESS_TOKEN_URI + "?client_id=218900b6c8d973881cf4185ecf&user_id=").given(req).getUri();

        // WHEN
        HttpResponse response = handler.handleGetAccessTokens(req);

        // THEN
        assertEquals(response.getContent().toString(CharsetUtil.UTF_8), String.format(Response.MANDATORY_PARAM_MISSING, "user_id"));
    }

    @Test
    public void when_get_tokens_client_id_invalid_return_invalid_client_id() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String userId = "214331231";
        String clientId = "218900b6c8d973881cf4185ecf";
        willReturn(HttpRequestHandler.ACCESS_TOKEN_URI + "?client_id=" + clientId + "&user_id=" + userId).given(req).getUri();
        AuthorizationServer auth = mock(AuthorizationServer.class);
        handler.auth = auth;
        willReturn(false).given(handler.auth).isActiveClientId(clientId);


        // WHEN
        HttpResponse response = handler.handleGetAccessTokens(req);

        // THEN
        assertEquals(response.getContent().toString(CharsetUtil.UTF_8), Response.INVALID_CLIENT_ID);
    }

    @Test
    public void when_get_tokens_invoke_get_token_by_user_and_client() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String userId = "214331231";
        String clientId = "218900b6c8d973881cf4185ecf";
        willReturn(HttpRequestHandler.ACCESS_TOKEN_URI + "?client_id=" + clientId + "&user_id=" + userId).given(req).getUri();
        AuthorizationServer auth = mock(AuthorizationServer.class);
        handler.auth = auth;
        willReturn(true).given(handler.auth).isExistingClient(clientId);
        MockDBManagerFactory.install();
        List<AccessToken> tokens = new ArrayList<AccessToken>();
        willReturn(tokens).given(DBManagerFactory.getInstance()).getAccessTokenByUserIdAndClientApp(userId, clientId);


        // WHEN
        HttpResponse response = handler.handleGetAccessTokens(req);

        // THEN
        verify(DBManagerFactory.getInstance()).getAccessTokenByUserIdAndClientApp(userId, clientId);
        assertEquals(response.getContent().toString(CharsetUtil.UTF_8), "[]");
    }

    private ChannelHandlerContext mockChannelHandlerContext() {
        ChannelHandlerContext ctx = mock(ChannelHandlerContext.class);
        Channel channel = mock(Channel.class);
        willReturn(channel).given(ctx).getChannel();
        ChannelFuture future = mock(ChannelFuture.class);
        willReturn(future).given(channel).write(anyObject());
        willDoNothing().given(future).addListener(ChannelFutureListener.CLOSE);
        return ctx;
    }

}
