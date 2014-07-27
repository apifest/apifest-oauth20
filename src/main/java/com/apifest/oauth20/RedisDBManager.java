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
package com.apifest.oauth20;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisSentinelPool;

public class RedisDBManager implements DBManager {
    private static Set<String> sentinels;
    private static JedisSentinelPool pool;
    private static String storeAuthCodeScript = "";
    private static String storeAuthCodeSHA;

    static {
        sentinels = new HashSet<String>();
        String[] sentinelsList = OAuthServer.getRedisSentinels().split(",");
        for (String sentinel : sentinelsList) {
            sentinels.add(sentinel);
        }
        pool = new JedisSentinelPool(OAuthServer.getRedisMaster(), sentinels);
    }

    public void setupDBManager() {
        Jedis jedis = pool.getResource();
        storeAuthCodeSHA = jedis.scriptLoad(storeAuthCodeScript);
        pool.returnResource(jedis);
    }

    @Override
    public boolean validClient(String clientId, String clientSecret) {
        Jedis jedis = pool.getResource();
        String secret = jedis.hget("cc:" + clientId, "secret");
        pool.returnResource(jedis);
        if (clientSecret.equals(secret)) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public void storeClientCredentials(ClientCredentials clientCreds) {
        Jedis jedis = pool.getResource();
        Map<String, String> credentials = new HashMap<String, String>();
        credentials.put("_id", clientCreds.getId());
        credentials.put("secret", clientCreds.getSecret());
        credentials.put("name", clientCreds.getName());
        credentials.put("uri", clientCreds.getUri());
        credentials.put("descr", clientCreds.getDescr());
        credentials.put("type", String.valueOf(clientCreds.getType()));
        credentials.put("status", String.valueOf(clientCreds.getStatus()));
        credentials.put("created", String.valueOf(clientCreds.getCreated()));
        credentials.put("scope", String.valueOf(clientCreds.getScope()));
        jedis.hmset("cc:" + clientCreds.getId(), credentials);
        pool.returnResource(jedis);
    }

    @Override
    public void storeAuthCode(AuthCode authCode) {
        Map<String, String> authCodeMap = new HashMap<String, String>();
        // authCode.id -> generate random or do not use it
        authCodeMap.put("_id", (authCode.getId() != null) ? authCode.getId() : "");
        authCodeMap.put("code", authCode.getCode());
        authCodeMap.put("clientId", authCode.getClientId());
        authCodeMap.put("redirectUri", authCode.getRedirectUri());
        authCodeMap.put("state", authCode.getState());
        authCodeMap.put("scope", authCode.getScope());
        authCodeMap.put("type", authCode.getType());
        authCodeMap.put("valid", String.valueOf(authCode.isValid()));
        authCodeMap.put("userId", authCode.getUserId());
        authCodeMap.put("created", authCode.getCreated().toString());
        Jedis jedis = pool.getResource();
        jedis.hmset("acc:" + authCode.getCode(), authCodeMap);
        // REVISIT: expires on auth code
        jedis.expire("acc:" + authCode.getCode(), 1800);
        jedis.hset("acuri:" + authCode.getCode() + authCode.getRedirectUri(), "ac",
                authCode.getCode());
        jedis.expire("acuri:" + authCode.getCode() + authCode.getRedirectUri(), 1800);
        pool.returnResource(jedis);
    }

    @Override
    public void updateAuthCodeValidStatus(String authCode, boolean valid) {
        Jedis jedis = pool.getResource();
        jedis.hset("acc:" + authCode, "valid", String.valueOf(valid));
        pool.returnResource(jedis);
    }

    @Override
    public void storeAccessToken(AccessToken accessToken) {
        Map<String, String> accessTokenMap = new HashMap<String, String>();
        accessTokenMap.put("token", accessToken.getToken());
        accessTokenMap.put("refreshToken", accessToken.getRefreshToken());
        accessTokenMap.put("expiresIn", accessToken.getExpiresIn());
        accessTokenMap.put("type", accessToken.getType());
        accessTokenMap.put("scope", accessToken.getScope());
        accessTokenMap.put("valid", String.valueOf(accessToken.isValid()));
        accessTokenMap.put("clientId", accessToken.getClientId());
        accessTokenMap.put("codeId", accessToken.getCodeId());
        accessTokenMap.put("userId", accessToken.getUserId());
        accessTokenMap.put("created", String.valueOf(accessToken.getCreated()));
        accessTokenMap.put("details", JSONUtils.convertListToJSON(accessToken.getDetails()));
        Jedis jedis = pool.getResource();
        jedis.hmset("at:" + accessToken.getToken(), accessTokenMap);
        jedis.expire("at:" + accessToken.getToken(), Integer.valueOf(accessToken.getExpiresIn()));
        jedis.hset("atr:" + accessToken.getRefreshToken() + accessToken.getClientId(),
                "access_token", accessToken.getToken());
        jedis.expire("atr:" + accessToken.getRefreshToken() + accessToken.getClientId(),
                Integer.valueOf(accessToken.getExpiresIn()));
        pool.returnResource(jedis);
    }

    @Override
    public AccessToken findAccessTokenByRefreshToken(String refreshToken, String clientId) {
        Jedis jedis = pool.getResource();
        String accessToken = jedis.hget("atr:" + refreshToken + clientId, "access_token");
        Map<String, String> accessTokenMap = jedis.hgetAll("at:" + accessToken);
        pool.returnResource(jedis);
        // REVISIT: check valid=true
        if (accessTokenMap.isEmpty() || "false".equals(accessTokenMap.get("valid"))) {
            return null;
        }
        return AccessToken.loadFromStringMap(accessTokenMap);
    }

    @Override
    public void updateAccessTokenValidStatus(String accessToken, boolean valid) {
        Jedis jedis = pool.getResource();
        jedis.hset("at:" + accessToken, "valid", String.valueOf(valid));
        pool.returnResource(jedis);
    }

    @Override
    public AccessToken findAccessToken(String accessToken) {
        Jedis jedis = pool.getResource();
        Map<String, String> accessTokenMap = jedis.hgetAll("at:" + accessToken);
        pool.returnResource(jedis);
        // REVISIT: Check valid=true
        if (accessTokenMap.isEmpty() || "false".equals(accessTokenMap.get("valid"))) {
            return null;
        }
        return AccessToken.loadFromStringMap(accessTokenMap);
    }

    @Override
    public AuthCode findAuthCode(String authCode, String redirectUri) {
        Jedis jedis = pool.getResource();
        // TODO: check by client_id too
        Map<String, String> authCodeIdMap = jedis.hgetAll("acuri:" + authCode + redirectUri);
        String authCodeId = authCodeIdMap.get("ac");
        Map<String, String> authCodeMap = jedis.hgetAll("acc:" + authCodeId);
        pool.returnResource(jedis);
        if (authCodeMap.isEmpty() || "false".equals(authCodeMap.get("valid"))) {
            return null;
        }
        return AuthCode.loadFromStringMap(authCodeMap);
    }

    @Override
    public ClientCredentials findClientCredentials(String clientId) {
        Jedis jedis = pool.getResource();
        Map<String, String> clientCredentialsMap = jedis.hgetAll("cc:" + clientId);
        pool.returnResource(jedis);
        if (clientCredentialsMap.isEmpty()) {
            return null;
        }
        return ClientCredentials.loadFromStringMap(clientCredentialsMap);
    }

    /*
     * @see com.apifest.oauth20.DBManager#storeScope(com.apifest.oauth20.Scope)
     */
    @Override
    public boolean storeScope(Scope scope) {
        Map<String, String> scopeMap = new HashMap<String, String>();
        scopeMap.put("id", scope.getScope());
        scopeMap.put(Scope.DESCRIPTION_FIELD, scope.getDescription());
        scopeMap.put(Scope.CC_EXPIRES_IN_FIELD, String.valueOf(scope.getCcExpiresIn()));
        scopeMap.put(Scope.PASS_EXPIRES_IN_FIELD, String.valueOf(scope.getPassExpiresIn()));
        Jedis jedis = pool.getResource();
        jedis.hmset("sc:" + scope.getScope(), scopeMap);
        return true;
    }

    /*
     * @see com.apifest.oauth20.DBManager#getAllScopes()
     */
    @Override
    public List<Scope> getAllScopes() {
        List<Scope> list = new ArrayList<Scope>();
        Jedis jedis = pool.getResource();
        Set<String> allScopes = jedis.keys("sc*");
        for (String scope : allScopes) {
            Map<String, String> scopeMap = jedis.hgetAll(scope);
            if (scopeMap.isEmpty()) {
                continue;
            } else {
                list.add(Scope.loadFromStringMap(scopeMap));
            }
        }
        pool.returnResource(jedis);
        return list;
    }

    /*
     * @see com.apifest.oauth20.DBManager#findScope(java.lang.String)
     */
    @Override
    public Scope findScope(String scopeName) {
        Jedis jedis = pool.getResource();
        Map<String, String> scopeMap = jedis.hgetAll("sc:" + scopeName);
        pool.returnResource(jedis);
        if (scopeMap.isEmpty()) {
            return null;
        }
        return Scope.loadFromStringMap(scopeMap);
    }

}
