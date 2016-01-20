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

package com.apifest.oauth20.persistence.hazelcast;

import java.util.Date;

import com.apifest.oauth20.AccessToken;
import com.apifest.oauth20.ApplicationInfo;
import com.apifest.oauth20.AuthCode;
import com.apifest.oauth20.ClientCredentials;
import com.apifest.oauth20.JsonUtils;
import com.apifest.oauth20.Scope;

/**
 * Transforms objects from/to persistence type objects.
 *
 * @author Apostol Terziev
 *
 */
public class PersistenceTransformations {

    public static Scope toScope(PersistentScope persistenceScope) {
        Scope scope = null;
        if (persistenceScope != null) {
            scope = new Scope();
            scope.setScope(persistenceScope.getScope());
            scope.setPassExpiresIn(persistenceScope.getPassExpiresIn());
            scope.setDescription(persistenceScope.getDescription());
            scope.setCcExpiresIn(persistenceScope.getCcExpiresIn());
            Integer refreshExpiresIn = persistenceScope.getRefreshExpiresIn() != null ? persistenceScope.getRefreshExpiresIn() : persistenceScope
                    .getPassExpiresIn();
            scope.setRefreshExpiresIn(refreshExpiresIn);
        }
        return scope;
    }

    public static PersistentScope toPersistentScope(Scope scope) {
        PersistentScope persistentScope = new PersistentScope();
        persistentScope.setScope(scope.getScope());
        persistentScope.setPassExpiresIn(scope.getPassExpiresIn());
        persistentScope.setDescription(scope.getDescription());
        persistentScope.setCcExpiresIn(scope.getCcExpiresIn());
        Integer refreshExpiresIn = scope.getRefreshExpiresIn() != null ? scope.getRefreshExpiresIn() : scope.getPassExpiresIn();
        persistentScope.setRefreshExpiresIn(refreshExpiresIn);
        return persistentScope;
    }

    public static ClientCredentials toClientCredentials(PersistentClientCredentials persistentClientCredentials) {
        ClientCredentials clientCredentials = null;
        if (persistentClientCredentials != null) {
            clientCredentials = new ClientCredentials();
            clientCredentials.setName(persistentClientCredentials.getName());
            clientCredentials.setScope(persistentClientCredentials.getScope());
            clientCredentials.setDescr(persistentClientCredentials.getDescr());
            clientCredentials.setUri(persistentClientCredentials.getUri());
            clientCredentials.setId(persistentClientCredentials.getId());
            clientCredentials.setSecret(persistentClientCredentials.getSecret());
            clientCredentials.setStatus(persistentClientCredentials.getStatus());
            clientCredentials.setType(persistentClientCredentials.getType());
            clientCredentials.setCreated(persistentClientCredentials.getCreated());
            clientCredentials.setApplicationDetails(persistentClientCredentials.getApplicationDetails());
        }
        return clientCredentials;
    }

    public static PersistentClientCredentials toPersistentClientCredentials(ClientCredentials clientCredentials) {
        PersistentClientCredentials persistentClientCredentials = new PersistentClientCredentials();
        persistentClientCredentials.setName(clientCredentials.getName());
        persistentClientCredentials.setScope(clientCredentials.getScope());
        persistentClientCredentials.setDescr(clientCredentials.getDescr());
        persistentClientCredentials.setUri(clientCredentials.getUri());
        persistentClientCredentials.setId(clientCredentials.getId());
        persistentClientCredentials.setSecret(clientCredentials.getSecret());
        persistentClientCredentials.setStatus(clientCredentials.getStatus());
        persistentClientCredentials.setType(clientCredentials.getType());
        persistentClientCredentials.setCreated(clientCredentials.getCreated());
        persistentClientCredentials.setApplicationDetails(clientCredentials.getApplicationDetails());
        return persistentClientCredentials;
    }

    public static PersistentAuthCode toPersistentAuthCode(AuthCode authCode) {
        PersistentAuthCode persistentAuthCode = new PersistentAuthCode();
        persistentAuthCode.setClientId(authCode.getClientId());
        persistentAuthCode.setCode(authCode.getCode());
        persistentAuthCode.setCreated(authCode.getCreated());
        persistentAuthCode.setId(authCode.getId());
        persistentAuthCode.setRedirectUri(authCode.getRedirectUri());
        persistentAuthCode.setScope(authCode.getScope());
        persistentAuthCode.setState(authCode.getState());
        persistentAuthCode.setType(authCode.getCode());
        persistentAuthCode.setUserId(authCode.getUserId());
        persistentAuthCode.setValid(authCode.isValid());
        return persistentAuthCode;
    }

    public static AuthCode toAuthCode(PersistentAuthCode persistentAuthCode) {
        AuthCode authCode = null;
        if (persistentAuthCode != null) {
            authCode = new AuthCode();
            authCode.setClientId(persistentAuthCode.getClientId());
            authCode.setCode(persistentAuthCode.getCode());
            authCode.setCreated(persistentAuthCode.getCreated());
            authCode.setId(persistentAuthCode.getId());
            authCode.setRedirectUri(persistentAuthCode.getRedirectUri());
            authCode.setScope(persistentAuthCode.getScope());
            authCode.setState(persistentAuthCode.getState());
            authCode.setType(persistentAuthCode.getCode());
            authCode.setUserId(persistentAuthCode.getUserId());
            authCode.setValid(persistentAuthCode.isValid());
        }
        return authCode;
    }

    public static PersistentAccessToken toPersistentAccessToken(AccessToken accessToken) {
        PersistentAccessToken persistentAccessToken = new PersistentAccessToken();
        persistentAccessToken.setClientId(accessToken.getClientId());
        persistentAccessToken.setCodeId(accessToken.getCodeId());
        persistentAccessToken.setCreated(accessToken.getCreated());
        persistentAccessToken.setExpiresIn(accessToken.getExpiresIn());
        persistentAccessToken.setRefreshToken(accessToken.getRefreshToken());
        persistentAccessToken.setScope(accessToken.getScope());
        persistentAccessToken.setToken(accessToken.getToken());
        persistentAccessToken.setType(accessToken.getType());
        persistentAccessToken.setUserId(accessToken.getUserId());
        persistentAccessToken.setValid(accessToken.isValid());
        persistentAccessToken.setDetails(JsonUtils.convertMapToJSON(accessToken.getDetails()));
        String refreshExpiresIn = (accessToken.getRefreshExpiresIn() != null && !accessToken.getRefreshExpiresIn().isEmpty()) ?
                accessToken.getRefreshExpiresIn() : accessToken.getExpiresIn();
        persistentAccessToken.setRefreshExpiresIn(refreshExpiresIn);
        return persistentAccessToken;
    }

    public static AccessToken toAccessToken(PersistentAccessToken persistentAccessToken) {
        AccessToken accessToken = null;
        if (persistentAccessToken != null) {
            accessToken = new AccessToken();
            accessToken.setClientId(persistentAccessToken.getClientId());
            accessToken.setCodeId(persistentAccessToken.getCodeId());
            accessToken.setCreated(persistentAccessToken.getCreated());
            accessToken.setExpiresIn(persistentAccessToken.getExpiresIn());
            accessToken.setRefreshToken(persistentAccessToken.getRefreshToken());
            accessToken.setScope(persistentAccessToken.getScope());
            accessToken.setToken(persistentAccessToken.getToken());
            accessToken.setType(persistentAccessToken.getType());
            accessToken.setUserId(persistentAccessToken.getUserId());
            accessToken.setValid(persistentAccessToken.isValid());
            accessToken.setDetails(JsonUtils.convertStringToMap(persistentAccessToken.getDetails()));
            String refreshExpiresIn = (persistentAccessToken.getRefreshExpiresIn() != null && !persistentAccessToken.getRefreshExpiresIn().isEmpty()) ?
                    persistentAccessToken .getRefreshExpiresIn() : persistentAccessToken.getExpiresIn();
            accessToken.setRefreshExpiresIn(refreshExpiresIn);
        }
        return accessToken;
    }

    public static ApplicationInfo toApplicationInfo(PersistentClientCredentials clientCredentials) {
        ApplicationInfo applicationInfo = new ApplicationInfo();
        applicationInfo.setName(clientCredentials.getName());
        applicationInfo.setScope(clientCredentials.getScope());
        applicationInfo.setDescription(clientCredentials.getDescr());
        applicationInfo.setRedirectUri(clientCredentials.getUri());
        applicationInfo.setId(clientCredentials.getId());
        applicationInfo.setSecret(clientCredentials.getSecret());
        applicationInfo.setStatus(clientCredentials.getStatus());
        applicationInfo.setRegistered(new Date(clientCredentials.getCreated()));
        applicationInfo.setApplicationDetails(clientCredentials.getApplicationDetails());
        return applicationInfo;
    }

}
