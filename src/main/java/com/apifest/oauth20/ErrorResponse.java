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

/**
 * Contains error responses.
 *
 * @author Rossitsa Borissova
 */
public final class ErrorResponse {
    public static final String CANNOT_REGISTER_APP = "{\"error\": \"cannot issue client_id and client_secret\"}";
    public static final String APPNAME_IS_NULL = "{\"error\": \"app_name parameter is mandatory\"}";
    public static final String INVALID_CLIENT_ID = "{\"error\": \"invalid client_id\"}";
    public static final String RESPONSE_TYPE_NOT_SUPPORTED = "{\"error\": \"unsupported_response_type\"}";
    public static final String INVALID_REDIRECT_URI = "{\"error\": \"invalid redirect_uri\"}";
    public static final String MANDATORY_PARAM_MISSING = "{\"error\": \"mandatory paramater %s is missing\"}";
    public static final String CANNOT_ISSUE_TOKEN = "{\"error\": \"cannot issue token\"}";
    public static final String INVALID_AUTH_CODE = "{\"error\": \"invalid auth_code\"}";
    public static final String GRANT_TYPE_NOT_SUPPORTED = "{\"error\": \"unsupported_grant_type\"}";
    public static final String INVALID_ACCESS_TOKEN = "{\"error\":\"invalid access token\"}";
    public static final String INVALID_REFRESH_TOKEN = "{\"error\":\"invalid refresh token\"}";
    public static final String INVALID_USERNAME_PASSWORD = "{\"error\": \"invalid username/password\"}";
    public static final String CANNOT_AUTHENTICATE_USER = "{\"error\": \"cannot authenticate user\"}";
}

