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

/**
 * @author Apostol Terziev
 */
package com.apifest.oauth20.persistence.redis;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.apifest.oauth20.AccessToken;
import com.apifest.oauth20.ApplicationInfo;
import com.apifest.oauth20.AuthCode;
import com.apifest.oauth20.ClientCredentials;
import com.apifest.oauth20.DBManager;
import com.apifest.oauth20.JsonUtils;
import com.apifest.oauth20.OAuthServer;
import com.apifest.oauth20.Scope;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.JedisSentinelPool;

public class RedisDBManager implements DBManager {

    /*
     * @see com.apifest.oauth20.DBManager#validClient(java.lang.String, java.lang.String)
     */
    @Override
    public boolean validClient(String clientId, String clientSecret) {
         ClientCredentials clientCredentials = findClientCredentials(clientId);
        if (clientSecret.equals(clientCredentials.getSecret()) && String.valueOf(ClientCredentials.ACTIVE_STATUS).equals(clientCredentials.getStatus())) {
            return true;
        } else {
            return false;
        }
    }

    /*
     * @see com.apifest.oauth20.DBManager#storeClientCredentials(com.apifest.oauth20.ClientCredentials)
     */
    @Override
    public void storeClientCredentials(ClientCredentials clientCreds) {
        List<String> parameters = new ArrayList<String>(10);
        parameters.add(clientCreds.getId());
        parameters.add(clientCreds.getSecret());
        parameters.add(clientCreds.getName());
        parameters.add(clientCreds.getUri());
        parameters.add(clientCreds.getDescr());
        parameters.add(String.valueOf(clientCreds.getType()));
        parameters.add(String.valueOf(clientCreds.getStatus()));
        parameters.add(String.valueOf(clientCreds.getCreated()));
        parameters.add(String.valueOf(clientCreds.getScope()));
        parameters.add(JsonUtils.convertMapToJSON(clientCreds.getApplicationDetails()));
        LuaScripts.runScript(ScriptType.STORE_CLIENT_CREDENTIALS, Collections.<String>emptyList(), parameters);
    }

    /*
     * @see com.apifest.oauth20.DBManager#storeAuthCode(com.apifest.oauth20.AuthCode)
     */
    @Override
    public void storeAuthCode(AuthCode authCode) {
        List<String> parameters = new ArrayList<String>(10);
        // authCode.id -> generate random or do not use it
        parameters.add((authCode.getId() != null) ? authCode.getId() : "");
        parameters.add(authCode.getCode());
        parameters.add(authCode.getClientId());
        parameters.add(authCode.getRedirectUri());
        parameters.add(authCode.getState());
        parameters.add(authCode.getScope());
        parameters.add(authCode.getType());
        parameters.add(String.valueOf(authCode.isValid()));
        parameters.add(authCode.getUserId());
        parameters.add(authCode.getCreated().toString());
        LuaScripts.runScript(ScriptType.STORE_AUTH_CODE, Collections.<String>emptyList(), parameters);
    }

    /*
     * @see com.apifest.oauth20.DBManager#updateAuthCodeValidStatus(java.lang.String, boolean)
     */
    @Override
    public void updateAuthCodeValidStatus(String authCode, boolean valid) {
        List<String> parameters = new ArrayList<String>(2);
        parameters.add(authCode);
        parameters.add(String.valueOf(valid));
        LuaScripts.runScript(ScriptType.UPDATE_AUTH_CODE_STATUS, Collections.<String>emptyList(), parameters);
    }

    /*
     * @see com.apifest.oauth20.DBManager#storeAccessToken(com.apifest.oauth20.AccessToken)
     */
    @Override
    public void storeAccessToken(AccessToken accessToken) {
        List<String> parameters = new ArrayList<String>(12);
        parameters.add(accessToken.getToken());
        parameters.add(accessToken.getRefreshToken());
        parameters.add(accessToken.getExpiresIn());
        parameters.add(accessToken.getType());
        parameters.add(accessToken.getScope());
        parameters.add(String.valueOf(accessToken.isValid()));
        parameters.add(accessToken.getClientId());
        parameters.add(accessToken.getCodeId());
        parameters.add(accessToken.getUserId());
        parameters.add(String.valueOf(accessToken.getCreated()));
        parameters.add(JsonUtils.convertMapToJSON(accessToken.getDetails()));
        parameters.add(accessToken.getRefreshExpiresIn());
        Integer tokenExpiration = Integer.valueOf((!accessToken.getRefreshExpiresIn().isEmpty()) ? accessToken.getRefreshExpiresIn() : accessToken.getExpiresIn());
        parameters.add(tokenExpiration.toString());

        Long uniqueId = System.currentTimeMillis();
        parameters.add(uniqueId.toString());
        LuaScripts.runScript(ScriptType.STORE_ACCESS_TOKEN, Collections.<String>emptyList(), parameters);
    }

    /*
     * @see com.apifest.oauth20.DBManager#findAccessTokenByRefreshToken(java.lang.String, java.lang.String)
     */
    @SuppressWarnings("unchecked")
    @Override
    public AccessToken findAccessTokenByRefreshToken(String refreshToken, String clientId) {
        List<String> parameters = new ArrayList<String>(2);
        parameters.add(refreshToken);
        parameters.add(clientId);
        List<String> accessTokenList = (List<String>) LuaScripts.runScript(ScriptType.ACCESS_TOKEN_BY_REFRESH_TOKEN, Collections.<String>emptyList(), parameters);
        if (accessTokenList == null || accessTokenList.isEmpty()) {
            return null;
        }
        return AccessToken.loadFromStringList(accessTokenList);
    }

    /*
     * @see com.apifest.oauth20.DBManager#updateAccessTokenValidStatus(java.lang.String, boolean)
     */
    @Override
    public void updateAccessTokenValidStatus(String accessToken, boolean valid) {
        List<String> parameters = new ArrayList<String>(2);
        parameters.add(accessToken);
        parameters.add(String.valueOf(valid));
        LuaScripts.runScript(ScriptType.UPDATE_ACCESS_TOKEN_STATUS, Collections.<String>emptyList(), parameters);
    }

    /*
     * @see com.apifest.oauth20.DBManager#findAccessToken(java.lang.String)
     */
    @SuppressWarnings("unchecked")
    @Override
    public AccessToken findAccessToken(String accessToken) {
        List<String> parameters = new ArrayList<String>(1);
        parameters.add(accessToken);
        List<String> accessTokenList = (List<String>) LuaScripts.runScript(ScriptType.FIND_ACCESS_TOKEN, Collections.<String>emptyList(), parameters);

        if (accessTokenList == null || accessTokenList.isEmpty() || "false".equals(accessTokenList.get(5))) { //Is it valid?
            return null;
        }
        return AccessToken.loadFromStringList(accessTokenList);
    }

    /*
     * @see com.apifest.oauth20.DBManager#findAuthCode(java.lang.String, java.lang.String)
     */
    @SuppressWarnings("unchecked")
    @Override
    public AuthCode findAuthCode(String authCode, String redirectUri) {
        List<String> parameters = new ArrayList<String>(2);
        parameters.add(authCode);
        parameters.add(redirectUri);
        List<String> authCodeList = (List<String>) LuaScripts.runScript(ScriptType.FIND_AUTH_CODE, Collections.<String>emptyList(), parameters);
        if (authCodeList == null || authCodeList.isEmpty() || "false".equals(authCodeList.get(5))) {
            return null;
        }
        return AuthCode.loadFromStringList(authCodeList);
    }

    /*
     * @see com.apifest.oauth20.DBManager#findClientCredentials(java.lang.String)
     */
    @SuppressWarnings("unchecked")
    @Override
    public ClientCredentials findClientCredentials(String clientId) {
        List<String> parameters = new ArrayList<String>(1);
        parameters.add(clientId);
        List<String> clientCredentialsList = (List<String>) LuaScripts.runScript(ScriptType.GET_CLIENT_CREDENTIALS, Collections.<String>emptyList(), parameters);
        if (clientCredentialsList == null || clientCredentialsList.isEmpty()) {
            return null;
        }
        return ClientCredentials.loadFromStringList(clientCredentialsList);
    }

    /*
     * @see com.apifest.oauth20.DBManager#storeScope(com.apifest.oauth20.Scope)
     */
    @Override
    public boolean storeScope(Scope scope) {
        List<String> parameters = new ArrayList<String>(5);
        parameters.add(scope.getScope());
        parameters.add(scope.getDescription());
        parameters.add(String.valueOf(scope.getCcExpiresIn()));
        parameters.add(String.valueOf(scope.getPassExpiresIn()));
        parameters.add(String.valueOf(scope.getRefreshExpiresIn()));
        LuaScripts.runScript(ScriptType.STORE_SCOPE, Collections.<String> emptyList(), parameters);
        return true;
    }

    /*
     * @see com.apifest.oauth20.DBManager#getAllScopes()
     */
    @SuppressWarnings("unchecked")
    @Override
    public List<Scope> getAllScopes() {
        List<Scope> list = new ArrayList<Scope>();
        List<String> allScopes = (List<String>) LuaScripts.runScript(ScriptType.GET_ALL_SCOPES, Collections.<String>emptyList(), Collections.<String>emptyList());
        for (String scope : allScopes) {
            list.add(findScope(scope.split(":")[1]));
        }
        return list;
    }

    /*
     * @see com.apifest.oauth20.DBManager#findScope(java.lang.String)
     */
    @Override
    public Scope findScope(String scopeName) {
        List<String> parameters = new ArrayList<String>(1);
        parameters.add(scopeName);
        @SuppressWarnings("unchecked")
        List<String> scopeList = (List<String>) LuaScripts.runScript(ScriptType.FIND_SCOPE, Collections.<String>emptyList(), parameters);
        if (scopeList == null || scopeList.isEmpty()) {
            return null;
        }
        return Scope.loadFromStringList(scopeList);
    }

    /*
     * @see com.apifest.oauth20.DBManager#updateClientAppScope(java.lang.String)
     */
    @Override
    public boolean updateClientApp(String clientId, String scope, String description, Integer status, Map<String, String> applicationDetails) {
        List<String> parameters = new ArrayList<String>(9);
        parameters.add(clientId);
        if (scope != null && scope.length() > 0) {
            parameters.add("scope");
            parameters.add(scope);
        }
        if (description != null && description.length() > 0) {
            parameters.add("descr");
            parameters.add(description);
        }
        if (status != null) {
            parameters.add("status");
            parameters.add(String.valueOf(status));
        }
        if(applicationDetails != null) {
            parameters.add("details");
            parameters.add(JsonUtils.convertMapToJSON(applicationDetails));
        }
        LuaScripts.runScript(ScriptType.UPDATE_APPLICATION, Collections.<String>emptyList(), parameters);
        return true;
    }

    /*
     * @see com.apifest.oauth20.DBManager#getAllApplications()
     */
    @SuppressWarnings("unchecked")
    @Override
    public List<ApplicationInfo> getAllApplications() {
        List<ApplicationInfo> list = new ArrayList<ApplicationInfo>();
        List<String> allApps = (List<String>) LuaScripts.runScript(ScriptType.GET_ALL_APPS, Collections.<String>emptyList(), Collections.<String>emptyList());
        if (allApps == null || allApps.isEmpty()) {
            return list;
        }
        for (String app : allApps) {
                ApplicationInfo creds = ApplicationInfo.loadFromClientCredentials(findClientCredentials(app.split(":")[1]));
                if (creds == null) {
                    continue;
                }
                list.add(creds);
        }
        return list;
    }

    /*
     * @see com.apifest.oauth20.DBManager#deleteScope(java.lang.String)
     */
    @Override
    public boolean deleteScope(String scopeName) {
        List<String> parameters = new ArrayList<String>(1);
        parameters.add(scopeName);
        Long deleted = (Long) LuaScripts.runScript(ScriptType.DEL_SCOPE, Collections.<String>emptyList(), parameters);
        // 1 if deleted, 0 - nothing deleted
        return (deleted.intValue() == 1) ? true : false;
    }

    /*
     * @see com.apifest.oauth20.DBManager#getAccessTokenByUserIdAndClientApp(java.lang.String, java.lang.String)
     */
    @SuppressWarnings("unchecked")
    @Override
    public List<AccessToken> getAccessTokenByUserIdAndClientApp(String userId, String clientId) {
        List<String> parameters = new ArrayList<String>(2);
        parameters.add(userId);
        parameters.add(clientId);
        List<List<String>> result = (List<List<String>>) LuaScripts.runScript(ScriptType.GET_AT_BY_USER_AND_APP, Collections.<String>emptyList(), parameters);
        List<AccessToken> accessTokens = new ArrayList<AccessToken>();
        if (result == null) {
            return accessTokens;
        }
        for (List<String> tokenList : result) {
            if (tokenList != null && !tokenList.isEmpty() && "true".equals(tokenList.get(5))) {
                accessTokens.add(AccessToken.loadFromStringList(tokenList));
            }
        }
        return accessTokens;
    }

    @Override
    public void removeAccessToken(String accessToken) {
        List<String> parameters = new ArrayList<String>(1);
        parameters.add(accessToken);
        LuaScripts.runScript(ScriptType.DEL_TOKEN, Collections.<String>emptyList(), parameters);
    }

}
