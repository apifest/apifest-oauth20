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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.testng.Assert.assertEquals;

import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.testng.annotations.Test;

/**
 * @author Rossitsa Borissova
 */
public class ResponseTest {

    @Test
    public void when_get_not_found_response_return_response_with_404_status() throws Exception {
        // WHEN
        HttpResponse response = Response.createNotFoundResponse();

        // THEN
        assertEquals(response.getStatus(), HttpResponseStatus.NOT_FOUND);
        assertEquals(response.headers().get(HttpHeaders.Names.CACHE_CONTROL),
                HttpHeaders.Values.NO_STORE);
        assertEquals(response.headers().get(HttpHeaders.Names.PRAGMA), HttpHeaders.Values.NO_CACHE);
    }

    @Test
    public void when_get_exception_response_get_exception_HTTP_status() throws Exception {
        // GIVEN
        OAuthException ex = mock(OAuthException.class);
        willReturn(Response.NAME_OR_SCOPE_OR_URI_IS_NULL).given(ex).getMessage();
        willReturn(HttpResponseStatus.BAD_REQUEST).given(ex).getHttpStatus();

        // WHEN
        HttpResponse response = Response.createOAuthExceptionResponse(ex);

        // THEN
        assertEquals(response.getStatus(), HttpResponseStatus.BAD_REQUEST);
        assertEquals(response.headers().get(HttpHeaders.Names.CACHE_CONTROL),
                HttpHeaders.Values.NO_STORE);
        assertEquals(response.headers().get(HttpHeaders.Names.PRAGMA), HttpHeaders.Values.NO_CACHE);
        assertEquals(response.headers().get(HttpHeaders.Names.CONTENT_LENGTH),
                String.valueOf(Response.NAME_OR_SCOPE_OR_URI_IS_NULL.getBytes().length));
        assertEquals(response.headers().get(HttpHeaders.Names.CONTENT_TYPE), "application/json");
        verify(ex).getMessage();
    }

    @Test
    public void when_create_response_with_message_set_content_type() throws Exception {
        // WHEN
        HttpResponse response = Response.createResponse(HttpResponseStatus.BAD_REQUEST, Response.ALREADY_REGISTERED_APP);

        // THEN
        assertEquals(response.headers().get(HttpHeaders.Names.CONTENT_TYPE), "application/json");
        assertEquals(response.headers().get(HttpHeaders.Names.CONTENT_LENGTH),
                String.valueOf(Response.ALREADY_REGISTERED_APP.getBytes().length));
        assertEquals(response.headers().get(HttpHeaders.Names.CACHE_CONTROL),
                HttpHeaders.Values.NO_STORE);
        assertEquals(response.headers().get(HttpHeaders.Names.PRAGMA), HttpHeaders.Values.NO_CACHE);
    }

    @Test
    public void when_create_unauthorized_response_set_headers() throws Exception {
        // WHEN
        HttpResponse response = Response.createUnauthorizedResponse();

        // THEN
        assertEquals(response.getStatus(), HttpResponseStatus.UNAUTHORIZED);
        assertEquals(response.headers().get(HttpHeaders.Names.CACHE_CONTROL),
                HttpHeaders.Values.NO_STORE);
        assertEquals(response.headers().get(HttpHeaders.Names.PRAGMA), HttpHeaders.Values.NO_CACHE);
        assertEquals(response.headers().get(HttpHeaders.Names.CONTENT_TYPE), "application/json");
        assertEquals(response.headers().get(HttpHeaders.Names.CONTENT_LENGTH),
                String.valueOf(Response.INVALID_ACCESS_TOKEN.getBytes().length));
    }

    @Test
    public void when_create_ok_response_with_message_set_headers() throws Exception {
        // WHEN
        HttpResponse response = Response.createOkResponse(Response.CLIENT_APP_UPDATED);

        // THEN
        assertEquals(response.getStatus(), HttpResponseStatus.OK);
        assertEquals(response.headers().get(HttpHeaders.Names.CACHE_CONTROL),
                HttpHeaders.Values.NO_STORE);
        assertEquals(response.headers().get(HttpHeaders.Names.PRAGMA), HttpHeaders.Values.NO_CACHE);
        assertEquals(response.headers().get(HttpHeaders.Names.CONTENT_TYPE), "application/json");
        assertEquals(response.headers().get(HttpHeaders.Names.CONTENT_LENGTH),
                String.valueOf(Response.CLIENT_APP_UPDATED.getBytes().length));
    }

    @Test
    public void when_create_not_found_response_set_headers() throws Exception {
        // WHEN
        HttpResponse response = Response.createNotFoundResponse();

        // THEN
        assertEquals(response.getStatus(), HttpResponseStatus.NOT_FOUND);
        assertEquals(response.headers().get(HttpHeaders.Names.CACHE_CONTROL),
                HttpHeaders.Values.NO_STORE);
        assertEquals(response.headers().get(HttpHeaders.Names.PRAGMA), HttpHeaders.Values.NO_CACHE);
        assertEquals(response.headers().get(HttpHeaders.Names.CONTENT_TYPE), "application/json");
        assertEquals(response.headers().get(HttpHeaders.Names.CONTENT_LENGTH),
                String.valueOf(Response.NOT_FOUND_CONTENT.getBytes().length));
    }

    @Test
    public void when_create_bad_request_response_with_message_set_headers() throws Exception {
        // WHEN
        HttpResponse response = Response.createBadRequestResponse(Response.CANNOT_REGISTER_APP);

        // THEN
        assertEquals(response.getStatus(), HttpResponseStatus.BAD_REQUEST);
        assertEquals(response.headers().get(HttpHeaders.Names.CACHE_CONTROL),
                HttpHeaders.Values.NO_STORE);
        assertEquals(response.headers().get(HttpHeaders.Names.PRAGMA), HttpHeaders.Values.NO_CACHE);
        assertEquals(response.headers().get(HttpHeaders.Names.CONTENT_TYPE), "application/json");
        assertEquals(response.headers().get(HttpHeaders.Names.CONTENT_LENGTH),
                String.valueOf(Response.CANNOT_REGISTER_APP.getBytes().length));
    }

    @Test
    public void when_create_bad_request_response_set_headers() throws Exception {
        // WHEN
        HttpResponse response = Response.createBadRequestResponse();

        // THEN
        assertEquals(response.getStatus(), HttpResponseStatus.BAD_REQUEST);
        assertEquals(response.headers().get(HttpHeaders.Names.CACHE_CONTROL),
                HttpHeaders.Values.NO_STORE);
        assertEquals(response.headers().get(HttpHeaders.Names.PRAGMA), HttpHeaders.Values.NO_CACHE);
    }

    @Test
    public void when_no_message_in_response_set_content_length_zero() throws Exception {
        // WHEN
        HttpResponse response = Response.createResponse(HttpResponseStatus.OK, null);

        // THEN
        assertEquals(response.headers().get(HttpHeaders.Names.CONTENT_LENGTH), "0");
    }
}
