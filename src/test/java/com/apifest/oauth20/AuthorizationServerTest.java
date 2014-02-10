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


import java.io.IOException;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpHeaders;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.slf4j.Logger;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;
import static org.mockito.BDDMockito.*;
import static org.testng.Assert.*;

/**
 * @author Rossitsa Borissova
 */
public class AuthorizationServerTest {

    AuthorizationServer authServer;

    @BeforeMethod
    public void setup() {
        AuthorizationServer.log = mock(Logger.class);
        authServer = spy(new AuthorizationServer());
        authServer.db = mock(DBManager.class);
        OAuthException.log = mock(Logger.class);
    }

    @Test
    public void when_client_id_not_registered_return_error_invalid_client_id() {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);

        // WHEN
        HttpResponseStatus status = null;
        String message = null;
        try {
            authServer.issueAuthorizationCode(req);
        } catch (OAuthException e) {
            status = e.getHttpStatus();
            message = e.getMessage();
        }

        // THEN
        assertEquals(status, HttpResponseStatus.BAD_REQUEST);
        assertEquals(message, ErrorResponse.INVALID_CLIENT_ID);
    }

    @Test
    public void when_response_type_not_supported_return_error_unsupported_response_type() {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        willReturn("http://localhost/oauth20/authorize?client_id=1232&response_type=no").given(req).getUri();
        willReturn(true).given(authServer).isValidClientId("1232");

        // WHEN
        HttpResponseStatus status = null;
        String message = null;
        try {
            authServer.issueAuthorizationCode(req);
        } catch (OAuthException e) {
            status = e.getHttpStatus();
            message = e.getMessage();
        }

        // THEN
        assertEquals(status, HttpResponseStatus.BAD_REQUEST);
        assertEquals(message, ErrorResponse.RESPONSE_TYPE_NOT_SUPPORTED);
    }

    @Test
    public void when_redirect_uri_not_valid_return_error_invalid_redirect_uri() {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        willReturn("http://localhost/oauth20/authorize?client_id=1232&response_type=code&redirect_uri=tp%3A%2F%2Fexample.com").given(req).getUri();
        willReturn(true).given(authServer).isValidClientId("1232");

        // WHEN
        HttpResponseStatus status = null;
        String message = null;
        try {
            authServer.issueAuthorizationCode(req);
        } catch (OAuthException e) {
            status = e.getHttpStatus();
            message = e.getMessage();
        }

        // THEN
        assertEquals(status, HttpResponseStatus.BAD_REQUEST);
        assertEquals(message, ErrorResponse.INVALID_REDIRECT_URI);
    }

    @Test
    public void when_valid_token_return_access_token() throws Exception {
        // GIVEN
        String token = "a9855207b560ac824dfb84f4d235243afdccfacaa3a32c66baeeec06eb0afa9c";
        AccessToken accessToken = mock(AccessToken.class);
        given(accessToken.getToken()).willReturn(token);
        given(authServer.db.findAccessToken(accessToken.getToken())).willReturn(accessToken);

        // WHEN
        AccessToken result = authServer.isValidToken(token);

        // THEN
        assertEquals(result, accessToken);
    }

    @Test
    public void when_not_valid_token_return_null() throws Exception {
        // GIVEN
        String token = "a9855207b560ac824dfb84f4d235243afdccfacaa3a32c66baeeec06eb0afa9c";

        // WHEN
        AccessToken result = authServer.isValidToken(token);

        // THEN
        assertNull(result);
    }

    @Test
    public void when_valid_client_id_return_true() throws Exception {
        // GIVEN
        String clientId = "203598599234220";
        given(authServer.db.findClientCredentials(clientId)).willReturn(mock(ClientCredentials.class));

        // WHEN
        boolean result = authServer.isValidClientId(clientId);

        // THEN
        assertTrue(result);
    }

    @Test
    public void when_not_valid_client_id_return_false() throws Exception {
        // GIVEN
        String clienId = "203598599234220";

        // WHEN
        boolean result = authServer.isValidClientId(clienId);

        // THEN
        assertFalse(result);
    }


    @Test
    public void when_issue_auth_code_validate_client_id() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String clientId = "203598599234220";
        given(authServer.db.findClientCredentials(clientId)).willReturn(mock(ClientCredentials.class));
        given(req.getUri()).willReturn("http://example.com/oauth20/authorize?client_id=" + clientId);

        // WHEN
        try {
            authServer.issueAuthorizationCode(req);
        } catch(OAuthException e) {
            // nothing to do
        }

        // THEN
        verify(authServer).isValidClientId(clientId);
    }


    @Test
    public void when_issue_auth_code_invoke_generate_code() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String clientId = "203598599234220";
        given(authServer.db.findClientCredentials(clientId)).willReturn(mock(ClientCredentials.class));
        given(req.getUri()).willReturn("http://example.com/oauth20/authorize?redirect_uri=http%3A%2F%2Fexample.com&response_type=code&client_id=" + clientId);

        // WHEN
        authServer.issueAuthorizationCode(req);

        // THEN
        verify(authServer).generateCode();
    }


    @Test
    public void when_issue_token_and_client_id_not_the_same_as_token_return_error() throws Exception {
        // GIVEN
        String clientId = "203598599234220";
        String redirectUri = "example.com";
        given(authServer.db.findClientCredentials(clientId)).willReturn(mock(ClientCredentials.class));

        String authCode = "eWPoZNvLxVDxuoVBCnGurPXefa#ttxKfryNbLPDvPFsFSkXVhreWW=HvULXWANTnhR=UEtkiaCxsOxgv_nTpqNWQFB-zGkQBHVoqQkjiWkyRuAHZWkFfn#sNeBhJVgOsR=F_vA" +
                "mJwoOh_ooe#ovaJVCOiZls_DzvkhOnRVrlDRSzZrbZIB_rwGXjpoeXdJlIjZQGhSR#";
        given(authServer.db.findAuthCode(authCode, redirectUri)).willReturn(mock(AuthCode.class));

        HttpRequest req = mock(HttpRequest.class);
        String content = "client_id=203598599234220&redirect_uri=" + redirectUri +
                "&grant_type=authorization_code&code=eWPoZNvLxVDxuoVBCnGurPXefa#ttxKfryNbLPDvPFsFSkXVhreWW=HvULXWANTnhR=UEtkiaCxsOxgv_nTpq" +
                "NWQFB-zGkQBHVoqQkjiWkyRuAHZWkFfn#sNeBhJVgOsR=F_vAmJwoOh_ooe#ovaJVCOiZls_DzvkhOnRVrlDRSzZrbZIB_rwGXjpoeXdJlIjZQGhSR#";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes());
        given(req.getContent()).willReturn(buf);
        willReturn(clientId).given(authServer).getBasicAuthenticationClientId(req);

        // WHEN
        String errorMsg = null;
        try {
            authServer.issueAccessToken(req);
        } catch(OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        verify(authServer).findAuthCode(any(TokenRequest.class));
        assertEquals(errorMsg, ErrorResponse.INVALID_CLIENT_ID);
    }

    @Test
    public void when_issue_token_validate_auth_code_and_client_id() throws Exception {
        // GIVEN
        String clientId = "203598599234220";
        String redirectUri = "example.com";
        given(authServer.db.findClientCredentials(clientId)).willReturn(mock(ClientCredentials.class));

        String code = "eWPoZNvLxVDxuoVBCnGurPXefa#ttxKfryNbLPDvPFsFSkXVhreWW=HvULXWANTnhR=UEtkiaCxsOxgv_nTpqNWQFB-zGkQBHVoqQkjiWkyRuAHZWkFfn#sNeBhJVgOsR=F_vA" +
                "mJwoOh_ooe#ovaJVCOiZls_DzvkhOnRVrlDRSzZrbZIB_rwGXjpoeXdJlIjZQGhSR#";
        AuthCode authCode = mock(AuthCode.class);
        given(authCode.getClientId()).willReturn(clientId);
        given(authServer.db.findAuthCode(code, redirectUri)).willReturn(authCode);

        HttpRequest req = mock(HttpRequest.class);
        String content = "redirect_uri=" + redirectUri +
                "&grant_type=authorization_code&code=eWPoZNvLxVDxuoVBCnGurPXefa#ttxKfryNbLPDvPFsFSkXVhreWW=HvULXWANTnhR=UEtkiaCxsOxgv_nTpq" +
                "NWQFB-zGkQBHVoqQkjiWkyRuAHZWkFfn#sNeBhJVgOsR=F_vAmJwoOh_ooe#ovaJVCOiZls_DzvkhOnRVrlDRSzZrbZIB_rwGXjpoeXdJlIjZQGhSR#";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes());
        given(req.getContent()).willReturn(buf);
        willReturn(clientId).given(authServer).getBasicAuthenticationClientId(req);

        // WHEN
        authServer.issueAccessToken(req);

        // THEN
        verify(authServer).findAuthCode(any(TokenRequest.class));
    }

    @Test
    public void when_issue_token_extract_client_id() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String content = "redirect_uri=example.com" +
                "&grant_type=authorization_code&code=eWPoZNvLxVDxuoVBCnGurPXefa#ttxKfryNbLPDvPFsFSkXVhreWW=HvULXWANTnhR=UEtkiaCxsOxgv_nTpq" +
                "NWQFB-zGkQBHVoqQkjiWkyRuAHZWkFfn#sNeBhJVgOsR=F_vAmJwoOh_ooe#ovaJVCOiZls_DzvkhOnRVrlDRSzZrbZIB_rwGXjpoeXdJlIjZQGhSR#";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes());
        given(req.getContent()).willReturn(buf);
        willReturn("203598599234220").given(authServer).getBasicAuthenticationClientId(req);

        // WHEN
        try {
            authServer.issueAccessToken(req);
        } catch(OAuthException e) {
            //nothing to do
        }

        // THEN
        verify(authServer).getBasicAuthenticationClientId(req);
    }

    @Test
    public void when_auth_code_not_valid_return_error() throws Exception {
        // GIVEN
        String clientId = "203598599234220";
        given(authServer.db.findClientCredentials(clientId)).willReturn(mock(ClientCredentials.class));

        HttpRequest req = mock(HttpRequest.class);
        String content = "client_id=203598599234220&redirect_uri=example.com" +
                "&grant_type=authorization_code&code=not_valid_code";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes());
        given(req.getContent()).willReturn(buf);
        willReturn(clientId).given(authServer).getBasicAuthenticationClientId(req);

        // WHEN
        String errorMsg = null;
        try {
            authServer.issueAccessToken(req);
        } catch(OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg, ErrorResponse.INVALID_AUTH_CODE);
    }

    @Test
    public void when_auth_code_for_another_redirect_uri_return_token() throws Exception {
        // GIVEN
        String clientId = "203598599234220";
        String redirectUri1 = "example1.com";
        String redirectUri2 = "example2.com";
        given(authServer.db.findClientCredentials(clientId)).willReturn(mock(ClientCredentials.class));

        String code = "eWPoZNvLxVDxuoVBCnGurPXefa#ttxKfryNbLPDvPFsFSkXVhreWW=HvULXWANTnhR=UEtkiaCxsOxgv_nTpqNWQFB-zGkQBHVoqQkjiWkyRuAHZWkFfn#sNeBhJVgOsR=F_vA" +
                "mJwoOh_ooe#ovaJVCOiZls_DzvkhOnRVrlDRSzZrbZIB_rwGXjpoeXdJlIjZQGhSR#";
        AuthCode authCode = mock(AuthCode.class);
        given(authCode.getClientId()).willReturn(clientId);
        given(authServer.db.findAuthCode(code, redirectUri1)).willReturn(authCode);
        given(authServer.db.findAuthCode(code, redirectUri2)).willReturn(authCode);

        HttpRequest req = mock(HttpRequest.class);
        String content = "redirect_uri=" + redirectUri2 +
                "&grant_type=authorization_code&code=eWPoZNvLxVDxuoVBCnGurPXefa#ttxKfryNbLPDvPFsFSkXVhreWW=HvULXWANTnhR=UEtkiaCxsOxgv_nTpq" +
                "NWQFB-zGkQBHVoqQkjiWkyRuAHZWkFfn#sNeBhJVgOsR=F_vAmJwoOh_ooe#ovaJVCOiZls_DzvkhOnRVrlDRSzZrbZIB_rwGXjpoeXdJlIjZQGhSR#";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes());
        given(req.getContent()).willReturn(buf);
        willReturn(clientId).given(authServer).getBasicAuthenticationClientId(req);

        // WHEN
        AccessToken token = authServer.issueAccessToken(req);

        // THEN
        verify(authServer.db).findAuthCode(code, redirectUri2);
        assertNotNull(token);
    }


    @Test
    public void when_register_store_appName() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        given(req.getUri()).willReturn("http://example.com/oauth20/register?app_name=TestDemoApp");
        willDoNothing().given(authServer.db).storeClientCredentials(any(ClientCredentials.class));

        // WHEN
        ClientCredentials creds = authServer.issueClientCredentials(req);

        // THEN
        verify(authServer.db).storeClientCredentials(any(ClientCredentials.class));
    }


    @Test
    public void when_no_app_name_passed_return_error() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        given(req.getUri()).willReturn("http://example.com/oauth20/register");

        // WHEN
        String errorMsg = null;
        try {
            authServer.issueClientCredentials(req);
        } catch(OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg, ErrorResponse.APPNAME_IS_NULL);
    }


    @Test
    public void when_client_is_registered_return_app_name() throws Exception {
        // GIVEN
        String clientId = "740503633355700";
        String appName = "TestDemoApp";
        ClientCredentials creds = mock(ClientCredentials.class);
        given(creds.getId()).willReturn(clientId);
        given(creds.getName()).willReturn(appName);
        given(authServer.db.findClientCredentials(clientId)).willReturn(creds);

        // WHEN
        String result = authServer.getApplicationName(clientId);

        // THEN
        assertEquals(result, appName);
    }

    @Test
    public void when_client_is_not_registered_return_null_app_name() throws Exception {
        // GIVEN
        String clientId = "not_registered_client_id";

        // WHEN
        String result = authServer.getApplicationName(clientId);

        // THEN
        assertNull(result);
    }

    @Test
    public void when_get_clientId_from_Basic_Auth_call_get_Header_method() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);

        // WHEN
        authServer.getBasicAuthenticationClientId(req);

        // THEN
        verify(req).getHeader(HttpHeaders.AUTHORIZATION);
    }

    @Test
    public void when_Basic_Auth_header_empty_return_null() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);

        // WHEN
        String clientId = authServer.getBasicAuthenticationClientId(req);

        // THEN
        assertNull(clientId);
    }

    @Test
    public void when_Basic_Auth_header_return_clientId() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String clientId = "740503633355700";
        String clientSecret = "7405036333557004234394sadasd214124";
        String basic = clientId + ":" + clientSecret;
        String headerValue = AuthorizationServer.BASIC + Base64.encodeBase64String(basic.getBytes());
        willReturn(headerValue).given(req).getHeader(HttpHeaders.AUTHORIZATION);
        willReturn(true).given(authServer.db).validClient(clientId, clientSecret);

        // WHEN
        String result = authServer.getBasicAuthenticationClientId(req);

        // THEN
        assertEquals(result, clientId);
    }


    @Test
    public void when_client_id_null_throw_exception() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        willReturn(null).given(authServer).getBasicAuthenticationClientId(req);

        // WHEN
        String errorMsg = null;
        try {
            authServer.issueAccessToken(req);
        } catch(OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg, ErrorResponse.INVALID_CLIENT_ID);
    }
    @Test
    public void when_issue_token_and_redirect_id_not_the_same_as_auth_code_return_error() throws Exception {
        // GIVEN
        String clientId = "203598599234220";
        String redirectUri = "example.com";
        String redirectUri2 = "example.com2222";
        given(authServer.db.findClientCredentials(clientId)).willReturn(mock(ClientCredentials.class));

        String authCode = "eWPoZNvLxVDxuoVBCnGurPXefa#ttxKfryNbLPDvPFsFSkXVhreWW=HvULXWANTnhR=UEtkiaCxsOxgv_nTpqNWQFB-zGkQBHVoqQkjiWkyRuAHZWkFfn#sNeBhJVgOsR=F_vA" +
                "mJwoOh_ooe#ovaJVCOiZls_DzvkhOnRVrlDRSzZrbZIB_rwGXjpoeXdJlIjZQGhSR#";
        AuthCode loadedCode = mock(AuthCode.class);
        given(loadedCode.getClientId()).willReturn(clientId);
        given(loadedCode.getRedirectUri()).willReturn(redirectUri);
        given(authServer.db.findAuthCode(authCode, redirectUri2)).willReturn(loadedCode);

        HttpRequest req = mock(HttpRequest.class);
        String content = "redirect_uri=" + redirectUri2 +
                "&grant_type=authorization_code&code=eWPoZNvLxVDxuoVBCnGurPXefa#ttxKfryNbLPDvPFsFSkXVhreWW=HvULXWANTnhR=UEtkiaCxsOxgv_nTpq" +
                "NWQFB-zGkQBHVoqQkjiWkyRuAHZWkFfn#sNeBhJVgOsR=F_vAmJwoOh_ooe#ovaJVCOiZls_DzvkhOnRVrlDRSzZrbZIB_rwGXjpoeXdJlIjZQGhSR#";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes());
        given(req.getContent()).willReturn(buf);
        willReturn(clientId).given(authServer).getBasicAuthenticationClientId(req);

        // WHEN
        String errorMsg = null;
        try {
            authServer.issueAccessToken(req);
        } catch(OAuthException e) {
            errorMsg = e.getMessage();
        }

        // THEN
        verify(authServer).findAuthCode(any(TokenRequest.class));
        assertEquals(errorMsg, ErrorResponse.INVALID_REDIRECT_URI);
    }

    @Test
    public void when_grant_type_refresh_token_update_original_access_token_status() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String refreshToken = "403b510679013ea1813b6fb5f76e7ddfedb8852d9eb8eef73";
        String content = "grant_type=" + TokenRequest.REFRESH_TOKEN + "&refresh_token=" + refreshToken;
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes());
        given(req.getContent()).willReturn(buf);
        String clientId = "203598599234220";
        willReturn(clientId).given(authServer).getBasicAuthenticationClientId(req);
        AccessToken accessToken = mock(AccessToken.class);
        willReturn("02d31ca13a0e448802b063ca2e16010b74b0e96ce9e05e953e").given(accessToken).getToken();
        willReturn(accessToken).given(authServer.db).findAccessTokenByRefreshToken(refreshToken, clientId);
        willDoNothing().given(authServer.db).updateAccessTokenValidStatus(anyString(), anyBoolean());
        willDoNothing().given(authServer.db).storeAccessToken(any(AccessToken.class));

        // WHEN
        AccessToken result = authServer.issueAccessToken(req);

        // THEN
        assertNotNull(result.getRefreshToken());
        verify(authServer.db).updateAccessTokenValidStatus(accessToken.getToken(), false);
    }

    @Test
    public void when_grant_type_client_credentials_issue_access_token_without_refresh_token() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String content = "grant_type=" + TokenRequest.CLIENT_CREDENTIALS + "&scope=basic";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes());
        given(req.getContent()).willReturn(buf);
        String clientId = "203598599234220";
        willReturn(clientId).given(authServer).getBasicAuthenticationClientId(req);
        willDoNothing().given(authServer.db).storeAccessToken(any(AccessToken.class));

        // WHEN
        AccessToken result = authServer.issueAccessToken(req);

        // THEN
        assertNull(result.getRefreshToken());
    }

    @Test
    public void when_grant_type_password_issue_access_token_with_refresh_token() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String content = "grant_type=" + TokenRequest.PASSWORD + "&username=rossi&password=test";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes());
        given(req.getContent()).willReturn(buf);
        String clientId = "203598599234220";
        willReturn(clientId).given(authServer).getBasicAuthenticationClientId(req);
        willDoNothing().given(authServer.db).storeAccessToken(any(AccessToken.class));
        willReturn("123456").given(authServer).authenticateUser("rossi", "test");

        // WHEN
        AccessToken result = authServer.issueAccessToken(req);

        // THEN
        assertNotNull(result.getRefreshToken());
    }

    @Test
    public void when_grant_type_password_and_auth_failed_return_error() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String content = "grant_type=" + TokenRequest.PASSWORD + "&username=rossi&password=test";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes());
        given(req.getContent()).willReturn(buf);
        String clientId = "203598599234220";
        willReturn(clientId).given(authServer).getBasicAuthenticationClientId(req);
        willReturn(null).given(authServer).authenticateUser("rossi", "test");

        // WHEN
        String errorMsg = null;
        try {
            authServer.issueAccessToken(req);
        } catch(OAuthException e){
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg, ErrorResponse.INVALID_USERNAME_PASSWORD);
    }

    @Test
    public void when_cannot_authenticate_user_return_error() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String content = "grant_type=" + TokenRequest.PASSWORD + "&username=rossi&password=test";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes());
        given(req.getContent()).willReturn(buf);
        String clientId = "203598599234220";
        willReturn(clientId).given(authServer).getBasicAuthenticationClientId(req);
        willThrow(new IOException("cannot connect")).given(authServer).authenticateUser("rossi", "test");

        // WHEN
        String errorMsg = null;
        try {
            authServer.issueAccessToken(req);
        } catch(OAuthException e){
            errorMsg = e.getMessage();
        }

        // THEN
        assertEquals(errorMsg, ErrorResponse.CANNOT_AUTHENTICATE_USER);
    }

    @Test
    public void when_issue_access_token_type_password_get_password_expires_in() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String content = "grant_type=" + TokenRequest.PASSWORD + "&username=rossi&password=test";
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes());
        given(req.getContent()).willReturn(buf);
        String clientId = "203598599234220";
        willReturn(clientId).given(authServer).getBasicAuthenticationClientId(req);
        willReturn("3232232122").given(authServer).authenticateUser("rossi", "test");

        // WHEN
        authServer.issueAccessToken(req);

        // THEN
        verify(authServer).getExpiresIn(TokenRequest.PASSWORD);
    }

    @Test
    public void when_issue_access_token_type_client_credentials_get_client_credentials_expires_in() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String content = "grant_type=" + TokenRequest.CLIENT_CREDENTIALS;
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes());
        given(req.getContent()).willReturn(buf);
        String clientId = "203598599234220";
        willReturn(clientId).given(authServer).getBasicAuthenticationClientId(req);

        // WHEN
        authServer.issueAccessToken(req);

        // THEN
        verify(authServer).getExpiresIn(TokenRequest.CLIENT_CREDENTIALS);
        assertEquals(authServer.getExpiresIn(TokenRequest.CLIENT_CREDENTIALS), "1800"); //default value for client_credentials token
    }

    @Test
    public void when_refresh_access_token_get_password_expires_in() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        String refreshToken = "403b510679013ea1813b6fb5f76e7ddfedb8852d9eb8eef73";
        String content = "grant_type=" + TokenRequest.REFRESH_TOKEN + "&refresh_token=" + refreshToken;
        ChannelBuffer buf = ChannelBuffers.copiedBuffer(content.getBytes());
        given(req.getContent()).willReturn(buf);
        String clientId = "203598599234220";
        willReturn(clientId).given(authServer).getBasicAuthenticationClientId(req);
        AccessToken accessToken = mock(AccessToken.class);
        willReturn("02d31ca13a0e448802b063ca2e16010b74b0e96ce9e05e953e").given(accessToken).getToken();
        willReturn(accessToken).given(authServer.db).findAccessTokenByRefreshToken(refreshToken, clientId);
        willDoNothing().given(authServer.db).updateAccessTokenValidStatus(anyString(), anyBoolean());
        willDoNothing().given(authServer.db).storeAccessToken(any(AccessToken.class));

        // WHEN
        authServer.issueAccessToken(req);

        // THEN
        verify(authServer).getExpiresIn(TokenRequest.PASSWORD);
        assertEquals(authServer.getExpiresIn(TokenRequest.PASSWORD), "900"); //default value for password token
    }

    @Test
    public void when_expired_token_update_valid_to_false() throws Exception {
        // GIVEN
        String token = "a9855207b560ac824dfb84f4d235243afdccfacaa3a32c66baeeec06eb0afa9c";
        AccessToken accessToken = mock(AccessToken.class);
        given(accessToken.getToken()).willReturn(token);
        given(authServer.db.findAccessToken(accessToken.getToken())).willReturn(accessToken);
        given(accessToken.isExpired()).willReturn(true);

        // WHEN
        AccessToken result = authServer.isValidToken(token);

        // THEN
        verify(authServer.db).updateAccessTokenValidStatus(accessToken.getToken(), false);
        assertNull(result);
    }

    @Test
    public void when_revoke_token_get_client_id_from_req_header() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        willReturn(null).given(authServer).getBasicAuthenticationClientId(req);

        // WHEN
        try {
            authServer.revokeToken(req);
        } catch(OAuthException e){
            // do nothing
        }

        // THEN
        verify(authServer).getBasicAuthenticationClientId(req);
    }

    @Test(expectedExceptions = OAuthException.class)
    public void when_revoke_token_with_client_id_null_will_throw_exception() throws Exception {
        // GIVEN
        HttpRequest req = mock(HttpRequest.class);
        willReturn(null).given(authServer).getBasicAuthenticationClientId(req);

        // WHEN
        authServer.revokeToken(req);
    }

    @Test
    public void when_revoke_token_get_access_token_null_return_false() throws Exception {
        // GIVEN
        String clientId = "203598599234220";
        HttpRequest req = mock(HttpRequest.class);
        willReturn(clientId).given(authServer).getBasicAuthenticationClientId(req);
        String token = "{\"access_token\":\"172ece50c15c8a2701ec20d17a22811d95c86af654f068858a7c140e69ad58f7\"}";
        ChannelBuffer buff = ChannelBuffers.copiedBuffer(token.getBytes());
        willReturn(buff).given(req).getContent();
        willReturn(null).given(authServer.db).findAccessToken("172ece50c15c8a2701ec20d17a22811d95c86af654f068858a7c140e69ad58f7");

        // WHEN
        boolean revoked = authServer.revokeToken(req);

        // THEN
        assertFalse(revoked);
    }

    @Test
    public void when_revoke_token_get_access_token_expired_then_return_true() throws Exception {
        // GIVEN
        String clientId = "203598599234220";
        HttpRequest req = mock(HttpRequest.class);
        willReturn(clientId).given(authServer).getBasicAuthenticationClientId(req);
        String token = "{\"access_token\":\"172ece50c15c8a2701ec20d17a22811d95c86af654f068858a7c140e69ad58f7\"}";
        ChannelBuffer buff = ChannelBuffers.copiedBuffer(token.getBytes());
        willReturn(buff).given(req).getContent();
        AccessToken accessToken = mock(AccessToken.class);
        willReturn(true).given(accessToken).isExpired();
        willReturn(accessToken).given(authServer.db).findAccessToken("172ece50c15c8a2701ec20d17a22811d95c86af654f068858a7c140e69ad58f7");

        // WHEN
        boolean revoked = authServer.revokeToken(req);

        // THEN
        assertTrue(revoked);
    }

    @Test
    public void when_revoke_token_get_access_token_not_expired_then_expire_it() throws Exception {
        // GIVEN
        String clientId = "203598599234220";
        HttpRequest req = mock(HttpRequest.class);
        willReturn(clientId).given(authServer).getBasicAuthenticationClientId(req);
        String token = "{\"access_token\":\"172ece50c15c8a2701ec20d17a22811d95c86af654f068858a7c140e69ad58f7\"}";
        ChannelBuffer buff = ChannelBuffers.copiedBuffer(token.getBytes());
        willReturn(buff).given(req).getContent();
        AccessToken accessToken = mock(AccessToken.class);
        willReturn(false).given(accessToken).isExpired();
        willReturn(clientId).given(accessToken).getClientId();
        willReturn(accessToken).given(authServer.db).findAccessToken("172ece50c15c8a2701ec20d17a22811d95c86af654f068858a7c140e69ad58f7");

        // WHEN
        boolean revoked = authServer.revokeToken(req);

        // THEN
        verify(authServer.db).updateAccessTokenValidStatus(accessToken.getToken(), false);
        assertTrue(revoked);
    }

    @Test
    public void when_revoke_token_issued_with_other_client_id_do_not_expire_and_return_false() throws Exception {
        // GIVEN
        String clientId = "203598599234220";
        HttpRequest req = mock(HttpRequest.class);
        willReturn(clientId).given(authServer).getBasicAuthenticationClientId(req);
        String token = "{\"access_token\":\"172ece50c15c8a2701ec20d17a22811d95c86af654f068858a7c140e69ad58f7\"}";
        ChannelBuffer buff = ChannelBuffers.copiedBuffer(token.getBytes());
        willReturn(buff).given(req).getContent();
        AccessToken accessToken = mock(AccessToken.class);
        willReturn(false).given(accessToken).isExpired();
        willReturn("0345901231313").given(accessToken).getClientId();
        willReturn(accessToken).given(authServer.db).findAccessToken("172ece50c15c8a2701ec20d17a22811d95c86af654f068858a7c140e69ad58f7");

        // WHEN
        boolean revoked = authServer.revokeToken(req);

        // THEN
        verify(authServer.db, times(0)).updateAccessTokenValidStatus(accessToken.getToken(), false);
        assertFalse(revoked);
    }
}
