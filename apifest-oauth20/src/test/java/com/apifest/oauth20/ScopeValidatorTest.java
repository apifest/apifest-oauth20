/*
 * Copyright 2013-2015, ApiFest project
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

import static org.testng.Assert.assertEquals;

import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.testng.annotations.Test;

/**
 * @author Rossitsa Borissova
 *
 */
public class ScopeValidatorTest {


    @Test
    public void when_cc_expires_in_is_not_integer_throw_exception() throws Exception {
        // GIVEN
        ScopeValidator validator = ScopeValidator.getInstance();

        // WHEN
        String errorMsg = null;
        HttpResponseStatus status = null;
        try {
            validator.validate(Scope.JSON_CC_EXPIRES_IN, "300a");
        } catch (OAuthException e) {
            errorMsg = e.getMessage();
            status = e.getHttpStatus();
        }

        // THEN
        assertEquals(errorMsg, String.format(Response.ERROR_NOT_INTEGER, Scope.JSON_CC_EXPIRES_IN));
        assertEquals(status, HttpResponseStatus.BAD_REQUEST);
    }

    @Test
    public void when_pass_expires_in_is_not_integer_throw_exception() throws Exception {
        // GIVEN
        ScopeValidator validator = ScopeValidator.getInstance();

        // WHEN
        String errorMsg = null;
        HttpResponseStatus status = null;
        try {
            validator.validate(Scope.JSON_PASS_EXPIRES_IN, "300a");
        } catch (OAuthException e) {
            errorMsg = e.getMessage();
            status = e.getHttpStatus();
        }

        // THEN
        assertEquals(errorMsg, String.format(Response.ERROR_NOT_INTEGER, Scope.JSON_PASS_EXPIRES_IN));
        assertEquals(status, HttpResponseStatus.BAD_REQUEST);
    }

    @Test
    public void when_refresh_expires_in_is_not_integer_throw_exception() throws Exception {
        // GIVEN
        ScopeValidator validator = ScopeValidator.getInstance();

        // WHEN
        String errorMsg = null;
        HttpResponseStatus status = null;
        try {
            validator.validate(Scope.JSON_REFRESH_EXPIRES_IN, "300a");
        } catch (OAuthException e) {
            errorMsg = e.getMessage();
            status = e.getHttpStatus();
        }

        // THEN
        assertEquals(errorMsg, String.format(Response.ERROR_NOT_INTEGER, Scope.JSON_REFRESH_EXPIRES_IN));
        assertEquals(status, HttpResponseStatus.BAD_REQUEST);
    }
}
