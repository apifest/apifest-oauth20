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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisSentinelPool;

public class RedisDBManager implements DBManager {
    private static Set<String> sentinels;
    private static JedisSentinelPool pool;
    private static String storeAuthCodeScriot = "";
    private static String storeAuthCodeSHA;

    static {
        sentinels = new HashSet<String>();
        String[] sentinelsList = OAuthServer.getRedisSentinels().split(",");
        for(String sentinel : sentinelsList) {
            sentinels.add(sentinel);
        }
        pool = new JedisSentinelPool(OAuthServer.getRedisMaster(), sentinels);
    }

    public void setupDBManager() {
        Jedis jedis = pool.getResource();
        storeAuthCodeSHA = jedis.scriptLoad(storeAuthCodeScriot);
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
        credentials.put("created", String.valueOf(clientCreds.getName()));
        jedis.hmset("cc:" + clientCreds.getId(), credentials);
        pool.returnResource(jedis);
    }

    @Override
    public void storeAuthCode(AuthCode authCode) {
        Map<String, String> authCodeMap = new HashMap<String, String>();
        authCodeMap.put("_id", authCode.getId());
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
        jedis.expire("acc:" + authCode.getCode(), 120);
        jedis.hset("acuri:" + authCode.getCode() + authCode.getRedirectUri(), "ac", authCode.getCode());
        jedis.expire("acuri:" + authCode.getCode() + authCode.getRedirectUri(), 120);
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
        Map<String, String> authCodeMap = new HashMap<String, String>();
        authCodeMap.put("token", accessToken.getToken());
        authCodeMap.put("refreshToken", accessToken.getRefreshToken());
        authCodeMap.put("expiresIn", accessToken.getToken());
        authCodeMap.put("type", accessToken.getToken());
        authCodeMap.put("scope", accessToken.getToken());
        authCodeMap.put("valid", accessToken.getToken());
        authCodeMap.put("clientId", accessToken.getToken());
        authCodeMap.put("codeId", accessToken.getToken());
        authCodeMap.put("userId", accessToken.getToken());
        authCodeMap.put("created", accessToken.getToken());
        Jedis jedis = pool.getResource();
        jedis.hmset("at:" + accessToken.getToken(), authCodeMap);
        jedis.expire("at:" + accessToken.getToken(), 120);
        jedis.hset("atr:" + accessToken.getRefreshToken() + accessToken.getClientId(), "access_token", accessToken.getToken());
        jedis.expire("atr:" + accessToken.getRefreshToken() + accessToken.getClientId(), 120);
        pool.returnResource(jedis);
    }

    @Override
    public AccessToken findAccessTokenByRefreshToken(String refreshToken, String clientId) {
        Jedis jedis = pool.getResource();
        String accessToken = jedis.hget("atr:" + refreshToken + clientId, "access_token");
        Map<String, String> accessTokenMap = jedis.hgetAll("at:" + accessToken);
        pool.returnResource(jedis);
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
        return AccessToken.loadFromStringMap(accessTokenMap);
    }

    @Override
    public AuthCode findAuthCode(String authCode, String redirectUri) {
        Jedis jedis = pool.getResource();
        Map<String, String> authCodeMap = jedis.hgetAll("acuri:" + authCode + redirectUri);
        pool.returnResource(jedis);
        return AuthCode.loadFromStringMap(authCodeMap);
    }

    @Override
    public ClientCredentials findClientCredentials(String clientId) {
        Jedis jedis = pool.getResource();
        Map<String, String> clientCredentialsMap = jedis.hgetAll("cc:" + clientId);
        pool.returnResource(jedis);
        return ClientCredentials.loadFromStringMap(clientCredentialsMap);
    }
}
