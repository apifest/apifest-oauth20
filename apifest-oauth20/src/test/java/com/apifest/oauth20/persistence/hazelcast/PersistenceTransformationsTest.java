/*
 * $Id$
 *
 * Copyright 2014 Skrill Ltd. All Rights Reserved.
 * SKRILL PROPRIETARY/CONFIDENTIAL. For internal use only.
 */
package com.apifest.oauth20.persistence.hazelcast;

import static org.mockito.BDDMockito.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

import org.testng.annotations.Test;

import com.apifest.oauth20.AccessToken;
import com.apifest.oauth20.AuthCode;
import com.apifest.oauth20.ClientCredentials;
import com.apifest.oauth20.Scope;

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
