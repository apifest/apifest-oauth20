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

package com.apifest.oauth20.persistence.hazelcast;

import static org.testng.Assert.assertNull;

import org.testng.annotations.Test;

import com.apifest.oauth20.AccessToken;
import com.apifest.oauth20.AuthCode;
import com.apifest.oauth20.ClientCredentials;
import com.apifest.oauth20.Scope;

/**
*
* @author Rossitsa Borissova
*/
public class PersistenceTransformationsTest {

    @Test
    public void when_no_client_credentials_found_return_null() throws Exception {
        // WHEN
        ClientCredentials clientCreds = PersistenceTransformations.toClientCredentials(null);

        // THEN
        assertNull(clientCreds);
    }

    @Test
    public void when_no_scope_found_return_null() throws Exception {
        // WHEN
        Scope scope = PersistenceTransformations.toScope(null);

        // THEN
        assertNull(scope);
    }

    @Test
    public void when_no_auth_code_found_return_null() throws Exception {
        // WHEN
        AuthCode authCode = PersistenceTransformations.toAuthCode(null);

        // THEN
        assertNull(authCode);
    }

    @Test
    public void when_no_access_token_found_return_null() throws Exception {
        // WHEN
        AccessToken token = PersistenceTransformations.toAccessToken(null);

        // THEN
        assertNull(token);
    }
}
