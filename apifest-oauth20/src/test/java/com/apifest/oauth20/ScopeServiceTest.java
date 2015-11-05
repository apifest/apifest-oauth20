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

import static org.mockito.BDDMockito.willReturn;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.handler.codec.http.DefaultHttpRequest;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpMethod;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.HttpVersion;
import org.jboss.netty.util.CharsetUtil;
import org.slf4j.Logger;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * @author Rossitsa Borissova
 */
public class ScopeServiceTest {

    ScopeService service;

    @BeforeMethod
    public void setup() {
        ScopeService.log = mock(Logger.class);
        service = spy(new ScopeService());
        MockDBManagerFactory.install();
    }

    @Test
    public void when_client_id_query_param_invoke_get_scopes_by_clientId() throws Exception {
        // GIVEN
        String clientId = "826064099791766";
        HttpRequest req = mock(HttpRequest.class);
        willReturn("http://localhost:8080/oauth20/scope?client_id=" + clientId).given(req).getUri();
        willReturn(null).given(service).getScopes(clientId);

        // WHEN
        service.getScopes(req);

        // THEN
        verify(service).getScopes(clientId);
    }

    @Test
    public void when_no_client_id_query_param_get_all_scopes() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        willReturn("http://localhost:8080/oauth20/scope").given(req).getUri();

        // WHEN
        service.getScopes(req);

        // THEN
        verify(service, never()).getScopes(anyString());
    }

    @Test
    public void when_get_all_scopes_invoke_load_all_scopes() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        willReturn("http://localhost:8080/oauth20/scope").given(req).getUri();

        // WHEN
        service.getScopes(req);

        // THEN
        verify(DBManagerFactory.dbManager).getAllScopes();
    }

    @Test
    public void when_get_client_scopes_invoke_scopes_for_that_client_only() throws Exception {
        // GIVEN
        String clientId = "826064099791766";
        HttpRequest req = mock(HttpRequest.class);
        willReturn("http://localhost:8080/oauth20/scope?client_id=" + clientId).given(req).getUri();
        String scope = "basic";
        ClientCredentials creds = new ClientCredentials("appName", scope, "descr", "http://example.com", null);
        willReturn(creds).given(DBManagerFactory.dbManager).findClientCredentials(clientId);

        // WHEN
        service.getScopes(req);

        // THEN
        verify(DBManagerFactory.dbManager).findClientCredentials(clientId);
        verify(DBManagerFactory.dbManager).findScope("basic");
    }

    @Test
    public void when_client_has_several_scopes_invoke_get_scope_details_for_each_scope()
            throws Exception {
        // GIVEN
        String clientId = "826064099791766";
        HttpRequest req = mock(HttpRequest.class);
        willReturn("http://localhost:8080/oauth20/scope?client_id=" + clientId).given(req).getUri();
        String scope = "basic extended";
        ClientCredentials creds = new ClientCredentials("appName", scope, "descr", "http://example.com", null);
        willReturn(creds).given(DBManagerFactory.dbManager).findClientCredentials(clientId);

        // WHEN
        service.getScopes(req);

        // THEN
        verify(DBManagerFactory.dbManager).findClientCredentials(clientId);
        verify(DBManagerFactory.dbManager).findScope("basic");
        verify(DBManagerFactory.dbManager).findScope("extended");
    }

    @Test
    public void when_scope_is_null_get_client_app_scope() throws Exception {
        // GIVEN
        String clientId = "826064099791766";
        MockDBManagerFactory.install();
        ClientCredentials creds = mock(ClientCredentials.class);
        willReturn("basic").given(creds).getScope();
        willReturn(creds).given(DBManagerFactory.getInstance()).findClientCredentials(clientId);

        // WHEN
        String scope = service.getValidScope(null, clientId);

        // THEN
        assertEquals(scope, "basic");
    }

    @Test
    public void when_scope_is_valid_check_client_app_scope_contains_it() throws Exception {
        // GIVEN
        String clientId = "826064099791766";
        MockDBManagerFactory.install();
        ClientCredentials creds = mock(ClientCredentials.class);
        willReturn("extended basic").given(creds).getScope();
        willReturn(creds).given(DBManagerFactory.getInstance()).findClientCredentials(clientId);

        // WHEN
        String scope = service.getValidScope("basic", clientId);

        // THEN
        assertEquals(scope, "basic");
    }

    @Test
    public void when_scope_is_not_contained_in_client_app_scope_return_null() throws Exception {
        // GIVEN
        String clientId = "826064099791766";
        MockDBManagerFactory.install();
        ClientCredentials creds = mock(ClientCredentials.class);
        willReturn("basic").given(creds).getScope();
        willReturn(creds).given(DBManagerFactory.getInstance()).findClientCredentials(clientId);

        // WHEN
        String scope = service.getValidScope("extended", clientId);

        // THEN
        assertNull(scope);
    }

    @Test
    public void when_scope_is_contained_return_true() throws Exception {
        // GIVEN
        String scope = "extended";
        String scopeList = "basic extended";

        // WHEN
        boolean allowed = service.scopeAllowed(scope, scopeList);

        // THEN
        assertTrue(allowed);
    }

    @Test
    public void when_scope_is_not_contained_return_false() throws Exception {
        // GIVEN
        String scope = "payment";
        String scopeList = "basic,extended";

        // WHEN
        boolean allowed = service.scopeAllowed(scope, scopeList);

        // THEN
        assertFalse(allowed);
    }

    @Test
    public void when_scope_contains_two_scopes_check_all() throws Exception {
        // GIVEN
        String scope = "basic extended";
        String scopeList = "basic extended";

        // WHEN
        boolean allowed = service.scopeAllowed(scope, scopeList);

        // THEN
        assertTrue(allowed);
    }

    @Test
    public void when_scope_with_CC_expires_in_900_return_900() throws Exception {
        // GIVEN
        String scopeName = "basic";
        Scope scope = new Scope();
        scope.setScope(scopeName);
        scope.setCcExpiresIn(900);
        scope.setPassExpiresIn(300);
        List<Scope> loadedScope = new ArrayList<Scope>();
        loadedScope.add(scope);
        willReturn(loadedScope).given(service).loadScopes(scopeName);

        // WHEN
        int result = service.getExpiresIn("client_credentials", scopeName);

        // THEN
        assertEquals(result, 900);
    }

    @Test
    public void when_scope_with_PASS_expires_in_300_return_300() throws Exception {
        // GIVEN
        String scopeName = "basic";
        Scope scope = new Scope();
        scope.setScope(scopeName);
        scope.setCcExpiresIn(900);
        scope.setPassExpiresIn(300);
        List<Scope> loadedScope = new ArrayList<Scope>();
        loadedScope.add(scope);
        willReturn(loadedScope).given(service).loadScopes(scopeName);

        // WHEN
        int result = service.getExpiresIn("password", scopeName);

        // THEN
        assertEquals(result, 300);
    }

    @Test
    public void when_several_scopes_and_pass_return_min_pass_expires_in() throws Exception {
        // GIVEN
        String scopeName = "basic extended";
        List<Scope> loadedScope = new ArrayList<Scope>();

        Scope scope1 = new Scope();
        scope1.setScope("basic");
        scope1.setCcExpiresIn(900);
        scope1.setPassExpiresIn(300);
        loadedScope.add(scope1);

        Scope scope2 = new Scope();
        scope2.setScope("extended");
        scope2.setCcExpiresIn(600);
        scope2.setPassExpiresIn(180);
        loadedScope.add(scope2);

        willReturn(loadedScope).given(service).loadScopes(scopeName);

        // WHEN
        int result = service.getExpiresIn("password", scopeName);

        // THEN
        assertEquals(result, 180);
    }

    @Test
    public void when_several_scopes_and_CC_return_min_CC_expires_in() throws Exception {
        // GIVEN
        String scopeName = "basic extended";
        List<Scope> loadedScope = new ArrayList<Scope>();

        Scope scope1 = new Scope();
        scope1.setScope("basic");
        scope1.setCcExpiresIn(900);
        scope1.setPassExpiresIn(300);
        loadedScope.add(scope1);

        Scope scope2 = new Scope();
        scope2.setScope("extended");
        scope2.setCcExpiresIn(600);
        scope2.setPassExpiresIn(180);
        loadedScope.add(scope2);

        willReturn(loadedScope).given(service).loadScopes(scopeName);

        // WHEN
        int result = service.getExpiresIn("client_credentials", scopeName);

        // THEN
        assertEquals(result, 600);
    }

    @Test
    public void when_no_loaded_scopes_and_CC_set_default_CC_expires_in() throws Exception {
        // GIVEN
        String scopeName = "not_existing";
        willReturn(Collections.EMPTY_LIST).given(service).loadScopes(scopeName);

        // WHEN
        int result = service.getExpiresIn("client_credentials", scopeName);

        // THEN
        assertEquals(result, OAuthServer.DEFAULT_CC_EXPIRES_IN);
    }

    @Test
    public void when_no_loaded_scopes_and_PASS_set_default_PASS_expires_in() throws Exception {
        // GIVEN
        String scopeName = "not_existing";
        willReturn(Collections.EMPTY_LIST).given(service).loadScopes(scopeName);

        // WHEN
        int result = service.getExpiresIn("password", scopeName);

        // THEN
        assertEquals(result, OAuthServer.DEFAULT_PASSWORD_EXPIRES_IN);
    }

    @Test
    public void when_scope_already_exists_trrows_already_exists_error() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String scopeName = "registered";
        String content = "{\"scope\":\"" + scopeName + "\",\"description\":\"test scope description\",\"cc_expires_in\":\"900\", \"pass_expires_in\":\"900\"}";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        willReturn(buf).given(req).getContent();

        HttpHeaders headers = mock(HttpHeaders.class);
        willReturn(Response.APPLICATION_JSON).given(headers).get(HttpHeaders.Names.CONTENT_TYPE);
        willReturn(headers).given(req).headers();

        Scope scope = mock(Scope.class);
        willReturn(scope).given(DBManagerFactory.dbManager).findScope(scopeName);

        // WHEN
        String errorMsg = null;
        try {
            service.registerScope(req);
        } catch(OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg, ScopeService.SCOPE_ALREADY_EXISTS);
    }

    @Test
    public void when_scope_not_valid_rerutn_error() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String scopeName = "registered";
        String content = "{\"scope\":\"" + scopeName + "\",\"description\":\"test scope description\",\"pass_expires_in\":\"900\"}";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        willReturn(buf).given(req).getContent();

        HttpHeaders headers = mock(HttpHeaders.class);
        willReturn(Response.APPLICATION_JSON).given(headers).get(HttpHeaders.Names.CONTENT_TYPE);
        willReturn(headers).given(req).headers();

        // WHEN
        String errorMsg = null;
        try {
            service.registerScope(req);
        } catch(OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg, ScopeService.MANDATORY_FIELDS_ERROR);
    }

    @Test
    public void when_content_type_NOT_application_json_return_unsupported_media_type() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String scopeName = "registered";
        String content = "{\"scope\":\"" + scopeName + "\",\"description\":\"test scope description\",\"pass_expires_in\":\"900\"}";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        willReturn(buf).given(req).getContent();

        // WHEN
        String errorMsg = null;
        try {
            service.registerScope(req);
        } catch(OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg, Response.UNSUPPORTED_MEDIA_TYPE);
    }

    @Test
    public void when_scope_not_exists_store_it() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String scopeName = "registered";
        String content = "{\"scope\":\"" + scopeName + "\",\"description\":\"test scope description\",\"cc_expires_in\":\"900\", \"pass_expires_in\":\"900\"}";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        willReturn(buf).given(req).getContent();

        HttpHeaders headers = mock(HttpHeaders.class);
        willReturn(Response.APPLICATION_JSON).given(headers).get(HttpHeaders.Names.CONTENT_TYPE);
        willReturn(headers).given(req).headers();

        willReturn(null).given(DBManagerFactory.dbManager).findScope(scopeName);
        willReturn(true).given(DBManagerFactory.dbManager).storeScope(any(Scope.class));

        // WHEN
        String storedMsg = service.registerScope(req);

        // THEN
        assertEquals(storedMsg, ScopeService.SCOPE_STORED_OK_MESSAGE);
    }

    @Test
    public void when_scope_not_successfully_registered_return_error() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String scopeName = "registered";
        String content = "{\"scope\":\"" + scopeName + "\",\"description\":\"test scope description\",\"cc_expires_in\":\"900\", \"pass_expires_in\":\"900\"}";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        willReturn(buf).given(req).getContent();

        HttpHeaders headers = mock(HttpHeaders.class);
        willReturn(Response.APPLICATION_JSON).given(headers).get(HttpHeaders.Names.CONTENT_TYPE);
        willReturn(headers).given(req).headers();

        willReturn(null).given(DBManagerFactory.dbManager).findScope(scopeName);
        willReturn(false).given(DBManagerFactory.dbManager).storeScope(any(Scope.class));

        // WHEN
        String storedMsg = service.registerScope(req);

        // THEN
        assertEquals(storedMsg, ScopeService.SCOPE_STORED_NOK_MESSAGE);
    }

    @Test
    public void when_update_not_existing_scope_return_scope_not_exist_error() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String scopeName = "registered";
        String content = "{\"description\":\"test scope description\",\"cc_expires_in\":\"900\", \"pass_expires_in\":\"900\"}";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        willReturn(buf).given(req).getContent();

        HttpHeaders headers = mock(HttpHeaders.class);
        willReturn(Response.APPLICATION_JSON).given(headers).get(HttpHeaders.Names.CONTENT_TYPE);
        willReturn(headers).given(req).headers();

        willReturn(null).given(DBManagerFactory.dbManager).findScope(scopeName);

        // WHEN
        String errorMsg = null;
        try {
            service.updateScope(req, scopeName);
        } catch(OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg, ScopeService.SCOPE_NOT_EXIST);
    }

    @Test
    public void when_update_scope_and_NOT_application_json_header_return_unsupported_media_error() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String scopeName = "registered";
        String content = "{\"description\":\"test scope description\",\"cc_expires_in\":\"900\", \"pass_expires_in\":\"900\"}";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        willReturn(buf).given(req).getContent();

        // WHEN
        String errorMsg = null;
        try {
            service.updateScope(req, scopeName);
        } catch(OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg, Response.UNSUPPORTED_MEDIA_TYPE);
    }

    @Test
    public void when_update_successfully_scope_return_updated_ok_message() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String scopeName = "registered";
        String content = "{\"description\":\"test scope description\",\"cc_expires_in\":\"900\", \"pass_expires_in\":\"900\"}";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        willReturn(buf).given(req).getContent();

        HttpHeaders headers = mock(HttpHeaders.class);
        willReturn(Response.APPLICATION_JSON).given(headers).get(HttpHeaders.Names.CONTENT_TYPE);
        willReturn(headers).given(req).headers();

        Scope scope = mock(Scope.class);
        willReturn(scope).given(DBManagerFactory.dbManager).findScope(scopeName);
        willReturn(true).given(DBManagerFactory.dbManager).storeScope(any(Scope.class));

        // WHEN
        String storedMsg = service.updateScope(req, scopeName);

        // THEN
        assertEquals(storedMsg, ScopeService.SCOPE_UPDATED_OK_MESSAGE);
    }

    @Test
    public void when_update_not_successfully_scope_return_updated_not_ok_message() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String scopeName = "registered";
        String content = "{\"description\":\"test scope description\",\"cc_expires_in\":\"900\", \"pass_expires_in\":\"900\"}";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        willReturn(buf).given(req).getContent();

        HttpHeaders headers = mock(HttpHeaders.class);
        willReturn(Response.APPLICATION_JSON).given(headers).get(HttpHeaders.Names.CONTENT_TYPE);
        willReturn(headers).given(req).headers();

        Scope scope = mock(Scope.class);
        willReturn(scope).given(DBManagerFactory.dbManager).findScope(scopeName);
        willReturn(false).given(DBManagerFactory.dbManager).storeScope(any(Scope.class));

        // WHEN
        String  updatedMsg = service.updateScope(req, scopeName);

        // THEN
        assertEquals(updatedMsg, ScopeService.SCOPE_UPDATED_NOK_MESSAGE);
    }

    @Test
    public void when_scope_with_no_description_set_it_from_the_stored_scope() throws Exception {
        // GIVEN
        Scope scope = new Scope();
        scope.setScope("scope");
        scope.setCcExpiresIn(1800);
        scope.setPassExpiresIn(900);

        Scope storedScope = new Scope();
        storedScope.setScope("scope");
        storedScope.setDescription("descr");
        storedScope.setCcExpiresIn(1800);
        storedScope.setPassExpiresIn(900);

        // WHEN
        service.setScopeEmptyValues(scope, storedScope);

        // THEN
        assertEquals(scope.getDescription(), "descr");
    }

    @Test
    public void when_scope_with_no_ccExpireseIn_set_it_from_the_stored_scope() throws Exception {
        // GIVEN
        Scope scope = new Scope();
        scope.setScope("scope");
        scope.setDescription("descr");
        scope.setPassExpiresIn(900);

        Scope storedScope = new Scope();
        storedScope.setScope("scope");
        storedScope.setDescription("descr");
        storedScope.setCcExpiresIn(1800);
        storedScope.setPassExpiresIn(900);

        // WHEN
        service.setScopeEmptyValues(scope, storedScope);

        // THEN
        assertTrue(scope.getCcExpiresIn() == 1800);
    }

    @Test
    public void when_scope_with_no_passExpireseIn_set_it_from_the_stored_scope() throws Exception {
        // GIVEN
        Scope scope = new Scope();
        scope.setScope("scope");
        scope.setDescription("descr");
        scope.setCcExpiresIn(1800);

        Scope storedScope = new Scope();
        storedScope.setScope("scope");
        storedScope.setDescription("descr");
        storedScope.setCcExpiresIn(1800);
        storedScope.setPassExpiresIn(900);

        // WHEN
        service.setScopeEmptyValues(scope, storedScope);

        // THEN
        assertTrue(scope.getPassExpiresIn() == 900);
    }

    @Test
    public void when_scope_with_passExpireseIn_do_not_update_it_from_stored_scope() throws Exception {
        // GIVEN
        Scope scope = new Scope();
        scope.setScope("scope");
        scope.setDescription("descr");
        scope.setCcExpiresIn(1800);
        scope.setPassExpiresIn(600);

        Scope storedScope = new Scope();
        storedScope.setScope("scope");
        storedScope.setDescription("descr");
        storedScope.setCcExpiresIn(1800);
        storedScope.setPassExpiresIn(900);

        // WHEN
        service.setScopeEmptyValues(scope, storedScope);

        // THEN
        assertTrue(scope.getPassExpiresIn() == 600);
    }

    @Test
    public void when_scope_with_no_refreshExpireseIn_set_it_from_the_stored_scope() throws Exception {
        // GIVEN
        Scope scope = new Scope();
        scope.setScope("scope");
        scope.setDescription("descr");
        scope.setCcExpiresIn(1800);

        Scope storedScope = new Scope();
        storedScope.setScope("scope");
        storedScope.setDescription("descr");
        storedScope.setCcExpiresIn(1800);
        storedScope.setPassExpiresIn(900);
        scope.setRefreshExpiresIn(3600);

        // WHEN
        service.setScopeEmptyValues(scope, storedScope);

        // THEN
        assertTrue(scope.getRefreshExpiresIn() == 3600);
    }

    @Test
    public void when_scope_with_refreshExpireseIn_do_not_update_it_from_stored_scope() throws Exception {
        // GIVEN
        Scope scope = new Scope();
        scope.setScope("scope");
        scope.setDescription("descr");
        scope.setCcExpiresIn(1800);
        scope.setPassExpiresIn(600);
        scope.setRefreshExpiresIn(6000);

        Scope storedScope = new Scope();
        storedScope.setScope("scope");
        storedScope.setDescription("descr");
        storedScope.setCcExpiresIn(1800);
        storedScope.setPassExpiresIn(900);
        storedScope.setRefreshExpiresIn(3600);

        // WHEN
        service.setScopeEmptyValues(scope, storedScope);

        // THEN
        assertTrue(scope.getRefreshExpiresIn() == 6000);
    }


    @Test
    public void when_register_scope_with_space_return_error() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String scopeName = "space scope";
        String content = "{\"scope\":\"" + scopeName + "\",\"description\":\"test scope description\",\"cc_expires_in\":\"900\", \"pass_expires_in\":\"900\"}";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        willReturn(buf).given(req).getContent();

        HttpHeaders headers = mock(HttpHeaders.class);
        willReturn(Response.APPLICATION_JSON).given(headers).get(HttpHeaders.Names.CONTENT_TYPE);
        willReturn(headers).given(req).headers();

        // WHEN
        String errorMsg = null;
        try {
            service.registerScope(req);
        } catch(OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg, ScopeService.SCOPE_NAME_INVALID_ERROR);
    }

    @Test
    public void when_db_delete_scope_return_false_return_delete_NOK_message() throws Exception {
        // GIVEN
        String scope = "scope";
        willReturn(mock(Scope.class)).given(DBManagerFactory.dbManager).findScope(scope);
        willReturn(false).given(DBManagerFactory.dbManager).deleteScope(scope);

        // WHEN
        String message = service.deleteScope(scope);

        // THEN
        assertEquals(message, ScopeService.SCOPE_DELETED_NOK_MESSAGE);
    }

    @Test
    public void when_db_delete_scope_return_true_return_delete_OK_message() throws Exception {
        // GIVEN
        String scope = "scope";
        willReturn(mock(Scope.class)).given(DBManagerFactory.dbManager).findScope(scope);
        willReturn(true).given(DBManagerFactory.dbManager).deleteScope(scope);

        // WHEN
        String message = service.deleteScope(scope);

        // THEN
        assertEquals(message, ScopeService.SCOPE_DELETED_OK_MESSAGE);
    }

    @Test
    public void when_scope_not_found_throw_exception() throws Exception {
        // GIVEN
        String scope = "scope";
        willReturn(null).given(DBManagerFactory.dbManager).findScope(scope);

        // WHEN
        OAuthException exception = null;
        try {
            service.deleteScope(scope);
        } catch(OAuthException e) {
            exception = e;
        }

        // THEN
        assertEquals(exception.getHttpStatus(), HttpResponseStatus.BAD_REQUEST);
        assertEquals(exception.getMessage(), ScopeService.SCOPE_NOT_EXIST);
    }

    @Test
    public void when_scope_is_registered_to_client_app_return_error_message() throws Exception {
        // GIVEN
        String scope = "scope";
        willReturn(mock(Scope.class)).given(DBManagerFactory.dbManager).findScope(scope);
        List<ClientCredentials> apps = new ArrayList<ClientCredentials>();
        apps.add(mock(ClientCredentials.class));
        willReturn(apps).given(service).getClientAppsByScope(scope);

        // WHEN
        String message = service.deleteScope(scope);

        // THEN
        assertEquals(message, ScopeService.SCOPE_USED_BY_APP_MESSAGE);
    }

    @Test
    public void when_application_uses_scope_add_it_to_result() throws Exception {
        // GIVEN
        String scope = "scope";
        List<ApplicationInfo> apps = new ArrayList<ApplicationInfo>();
        ApplicationInfo app = mock(ApplicationInfo.class);
        willReturn("someScope" + " " + scope).given(app).getScope();
        apps.add(app);
        willReturn(apps).given(DBManagerFactory.dbManager).getAllApplications();

        // WHEN
        List<ApplicationInfo> scopeApps = service.getClientAppsByScope(scope);

        // THEN
        assertTrue(scopeApps.size() == 1);
    }

    @Test
    public void when_no_application_uses_scope_return_empty_list() throws Exception {
        // GIVEN
        String scope = "scope";
        List<ApplicationInfo> apps = new ArrayList<ApplicationInfo>();
        ApplicationInfo app = mock(ApplicationInfo.class);
        willReturn("someScope").given(app).getScope();
        apps.add(app);
        willReturn(apps).given(DBManagerFactory.dbManager).getAllApplications();

        // WHEN
        List<ApplicationInfo> scopeApps = service.getClientAppsByScope(scope);

        // THEN
        assertTrue(scopeApps.size() == 0);
    }

    @Test
    public void when_get_scopes_with_invalid_client_id_throw_oauth_exception_with_not_found_status() throws Exception {
        // GIVEN
        String clientId = "203598599234220";
        HttpRequest req = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, HttpRequestHandler.OAUTH_CLIENT_SCOPE_URI + "?client_id=" + clientId);
        req.headers().add(HttpHeaders.Names.CONTENT_TYPE, "application/json");
        String content = "any content here";
        req.setContent(ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8)));
        willReturn(null).given(DBManagerFactory.dbManager).findClientCredentials(clientId);

        // WHEN
        HttpResponseStatus status = null;
        try {
            service.getScopes(req);
        } catch (OAuthException e) {
            status = e.getHttpStatus();
        }

        // THEN
        verify(DBManagerFactory.dbManager, times(0)).getAllScopes();
        assertEquals(status, HttpResponseStatus.NOT_FOUND);
    }

    @Test
    public void when_GET_non_existing_scope_by_name_return_error_scope_does_not_exist_message() throws Exception {
        // GIVEN
        String scope = "scope";
        willReturn(null).given(DBManagerFactory.dbManager).findScope(scope);

        // WHEN
        String errorMessage = null;
        HttpResponseStatus errorStatus = null;
        try {
            service.getScopeByName(scope);
        } catch (OAuthException e) {
            errorMessage = e.getMessage();
            errorStatus = e.getHttpStatus();
        }

        // THEN
        assertEquals(errorMessage, ScopeService.SCOPE_NOT_EXIST);
        assertEquals(errorStatus, HttpResponseStatus.NOT_FOUND);
    }

    @Test
    public void when_scope_with_refresh_expires_in_1800_return_1800() throws Exception {
        // GIVEN
        String scopeName = "basic";
        Scope scope = new Scope();
        scope.setScope(scopeName);
        scope.setCcExpiresIn(900);
        scope.setPassExpiresIn(300);
        scope.setRefreshExpiresIn(1800);
        List<Scope> loadedScope = new ArrayList<Scope>();
        loadedScope.add(scope);
        willReturn(loadedScope).given(service).loadScopes(scopeName);

        // WHEN
        int result = service.getExpiresIn("refresh_token", scopeName);

        // THEN
        assertEquals(result, 1800);
    }

    @Test
    public void when_scope_with_no_refresh_expires_in_set_it_from_the_stored_scope() throws Exception {
        // GIVEN
        Scope scope = new Scope();
        scope.setScope("scope");
        scope.setCcExpiresIn(1800);
        scope.setPassExpiresIn(900);

        Scope storedScope = new Scope();
        storedScope.setScope("scope");
        storedScope.setDescription("descr");
        storedScope.setCcExpiresIn(1800);
        storedScope.setPassExpiresIn(900);
        storedScope.setRefreshExpiresIn(3600);

        // WHEN
        service.setScopeEmptyValues(scope, storedScope);

        // THEN
        assertTrue(scope.getRefreshExpiresIn() == 3600);
    }


    @Test
    public void when_register_scope_invoke_input_validator() throws Exception {
        // GIVEN
        MockScopeValidator.install();
        HttpRequest req = mock(HttpRequest.class);
        int paramsCount = 4;
        String scopeName = "test_scope";
        String content = "{\"scope\":\"" + scopeName + "\",\"description\":\"test scope description\",\"cc_expires_in\":\"900\", \"pass_expires_in\":\"900\"}";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        willReturn(buf).given(req).getContent();

        HttpHeaders headers = mock(HttpHeaders.class);
        willReturn(Response.APPLICATION_JSON).given(headers).get(HttpHeaders.Names.CONTENT_TYPE);
        willReturn(headers).given(req).headers();

        willReturn(null).given(DBManagerFactory.dbManager).findScope(scopeName);
        willReturn(true).given(DBManagerFactory.dbManager).storeScope(any(Scope.class));

        // WHEN
        service.registerScope(req);

        // THEN
        verify(ScopeValidator.getInstance(), times(paramsCount)).validate(anyString(), anyString());

        MockScopeValidator.deinstall();
    }

    @Test
    public void when_update_scope_invoke_input_validator() throws Exception {
        // GIVEN
        MockScopeValidator.install();
        HttpRequest req = mock(HttpRequest.class);
        String scopeName = "test_scope";
        int paramsCount = 1;
        String content = "{\"description\":\"new description\"}";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes(CharsetUtil.UTF_8));
        willReturn(buf).given(req).getContent();

        HttpHeaders headers = mock(HttpHeaders.class);
        willReturn(Response.APPLICATION_JSON).given(headers).get(HttpHeaders.Names.CONTENT_TYPE);
        willReturn(headers).given(req).headers();

        Scope scope = mock(Scope.class);
        willReturn(scope).given(DBManagerFactory.dbManager).findScope(scopeName);
        willReturn(true).given(DBManagerFactory.dbManager).storeScope(any(Scope.class));

        // WHEN
        service.updateScope(req, scopeName);

        // THEN
        verify(ScopeValidator.getInstance(), times(paramsCount)).validate(anyString(), anyString());

        MockScopeValidator.deinstall();
    }
}
