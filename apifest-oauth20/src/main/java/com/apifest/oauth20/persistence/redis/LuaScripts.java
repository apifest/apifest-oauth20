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

import java.security.InvalidParameterException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisSentinelPool;
import redis.clients.jedis.exceptions.JedisDataException;

public class LuaScripts {
    private static final String STORE_CLIENT_CREDENTIALS_SCRIPT = ""
            + "local _id = ARGV[1]; "
            + "local secret = ARGV[2]; "
            + "local name = ARGV[3]; "
            + "local uri = ARGV[4]; "
            + "local descr = ARGV[5]; "
            + "local type = ARGV[6]; "
            + "local status = ARGV[7]; "
            + "local created = ARGV[8]; "
            + "local scope = ARGV[9]; "
            + "local details = ARGV[10]; "
            + "redis.call('HMSET','cc:'.._id, '_id',_id,'secret',secret,'name',name,'uri',uri,'descr',descr,'type',type,'status',status,'created',created,'scope',scope,'details',details);";

    private static final String STORE_SCOPE_SCRIPT = ""
            + "local id = ARGV[1]; "
            + "local description = ARGV[2]; "
            + "local ccExpiresIn = ARGV[3]; "
            + "local passExpiresIn = ARGV[4]; "
            + "local refreshExpiresIn = ARGV[5]; "
            + "redis.call('HMSET', 'sc:'..id,'id',id,'description',description,'ccExpiresIn',ccExpiresIn,'passExpiresIn',passExpiresIn,'refreshExpiresIn',refreshExpiresIn);";

    private static final String FIND_SCOPE_SCRIPT = ""
            + "local id = ARGV[1]; "
            + "if redis.call('EXISTS','sc:'..id) == 0 then "
            + "  return nil; "
            + "end "
            + "return redis.call('HMGET', 'sc:'..id,'id','description','ccExpiresIn','passExpiresIn','refreshExpiresIn');";

    private static final String GET_ALL_SCOPES_SCRIPT = ""
            + "return redis.call('KEYS', 'sc:*');";

    private static final String DEL_SCOPE_SCRIPT = ""
            + "local id = ARGV[1]; "
            + "return redis.call('DEL', 'sc:'..id);";

    private static final String GET_ALL_APPS_SCRIPT = ""
            + "return redis.call('KEYS', 'cc:*');";

    private static final String GET_CLIENT_CREDENTIALS_SCRIPT = ""
            + "local id = ARGV[1]; "
            + "if redis.call('EXISTS','cc:'..id) == 0 then "
            + "  return nil; "
            + "end "
            + "return redis.call('HMGET', 'cc:'..id,'_id','secret','name','uri','descr','type','status','created','scope','details');";

    private static final String UPDATE_APPLICATION_SCRIPT = ""
            + "local id = ARGV[1]; "
            + "local i = 2; "
            + "while ARGV[i] do "
            + "  redis.call('HMSET', 'cc:'..id, ARGV[i], ARGV[i + 1]);"
            + "  i = i + 2;"
            + "end ";

    private static final String STORE_ACCESS_TOKEN_SCRIPT = ""
            + "local token = ARGV[1]; "
            + "local refreshToken = ARGV[2]; "
            + "local expiresIn = ARGV[3]; "
            + "local type = ARGV[4]; "
            + "local scope = ARGV[5]; "
            + "local valid = ARGV[6]; "
            + "local clientId = ARGV[7]; "
            + "local codeId = ARGV[8]; "
            + "local userId = ARGV[9]; "
            + "local created = ARGV[10]; "
            + "local details = ARGV[11]; "
            + "local refreshExpiresIn = ARGV[12]; "
            + "local tokenExpiration = tonumber(ARGV[13]); "
            + "local unique = ARGV[14]; "
            + "redis.call('HMSET','at:'..token,'token',token,'refreshToken',refreshToken,'expiresIn',expiresIn,'type',type,'scope',scope,'valid',valid,'clientId',clientId,'codeId',codeId,'userId',userId,'created',created,'details',details,'refreshExpiresIn',refreshExpiresIn); "
            + "redis.call('EXPIRE', 'at:'..token, tokenExpiration); "
            + "redis.call('HSET', 'atr:'..refreshToken..clientId, 'access_token', token); "
            + "redis.call('EXPIRE', 'atr:'..refreshToken..clientId, tokenExpiration); "
            + "redis.call('HSET', 'atuid:'..userId..':'..clientId..unique, 'access_token', token); "
            + "redis.call('EXPIRE', 'atuid:'..userId..':'..clientId..unique, tokenExpiration);";

    private static final String FIND_ACCESS_TOKEN_SCRIPT = ""
            + "local token = ARGV[1]; "
            + "if redis.call('EXISTS','at:'..token) == 0 then "
            + "  return nil; "
            + "end "
            + "return redis.call('HMGET','at:'..token,'token','refreshToken','expiresIn','type','scope','valid','clientId','codeId','userId','created','details','refreshExpiresIn'); ";

    private static final String STORE_AUTH_CODE_SCRIPT = ""
            + "local _id = ARGV[1]; "
            + "local code = ARGV[2]; "
            + "local clientId = ARGV[3]; "
            + "local redirectUri = ARGV[4]; "
            + "local state = ARGV[5]; "
            + "local scope = ARGV[6]; "
            + "local type = ARGV[7]; "
            + "local valid = ARGV[8]; "
            + "local userId = ARGV[9]; "
            + "local created = ARGV[10]; "
            + "redis.call('HMSET','acc:'..code,'_id',_id,'code',code,'clientId',clientId,'redirectUri',redirectUri,'state',state,'scope',scope,'type',type,'valid',valid,'userId',userId,'created',created); "
            + "redis.call('EXPIRE', 'acc:'..code, 1800); "
            + "redis.call('HSET', 'acuri:'..code..redirectUri, 'ac', code); "
            + "redis.call('EXPIRE', 'acuri:'..code..redirectUri, 1800); ";

    private static final String UPDATE_AUTH_CODE_STATUS_SCRIPT = ""
            + "local auth_code = ARGV[1]; "
            + "local valid = ARGV[2]; "
            + "redis.call('HSET','acc:'..auth_code,'valid', valid); ";

    private static final String ACCESS_TOKEN_BY_REFRESH_TOKEN_SCRIPT = ""
            + "local refresh_token = ARGV[1]; "
            + "local client_id = ARGV[2]; "
            + "if redis.call('EXISTS','atr:'..refresh_token..client_id) == 0 then "
            + "  return nil; "
            + "end "
            + "local token = redis.call('HGET','atr:'..refresh_token..client_id,'access_token'); "
            + "if redis.call('EXISTS','at:'..token) == 0 then "
            + "  return nil; "
            + "end "
            + "return redis.call('HMGET','at:'..token,'token','refreshToken','expiresIn','type','scope','valid','clientId','codeId','userId','created','details','refreshExpiresIn'); ";

    private static final String UPDATE_ACCESS_TOKEN_STATUS_SCRIPT = ""
            + "local access_token = ARGV[1]; "
            + "local valid = ARGV[2]; "
            + "redis.call('HSET','at:'..access_token,'valid', valid); ";

    private static final String FIND_AUTH_CODE_SCRIPT = ""
            + "local auth_code = ARGV[1]; "
            + "local redirec_uri = ARGV[2]; "
            + "if redis.call('EXISTS','acuri:'..auth_code..redirec_uri) == 0 then "
            + "  return nil; "
            + "end "
            + "local access_code_id = redis.call('HGET','acuri:'..auth_code..redirec_uri,'ac'); "
            + "if redis.call('EXISTS','acc:'..access_code_id) == 0 then "
            + "  return nil; "
            + "end "
            + "return redis.call('HMGET','acc:'..access_code_id,'_id','code','clientId','redirectUri','state','scope','type','valid','userId','created');";

    private static final String GET_AT_BY_USER_AND_APP_SCRIPT = ""
            + "local user_id = ARGV[1]; "
            + "local client_id = ARGV[2]; "
            + "local result = {}; "
            + "if redis.call('EXISTS','atuid:'..user_id..':'..client_id) == 0 then "
            + "  return nil; "
            + "end "
            + "local keys = redis.call('KEYS','atuid:'..user_id..':'..client_id..':*'); "
            + "for i,v in ipairs(keys) do "
            + "  local token_id = redis.call('HGET', v, 'access_token'); "
            + "  local token = redis.call('HMGET','at:'..token_id,'token','refreshToken','expiresIn','type','scope','valid','clientId','codeId','userId','created','details','refreshExpiresIn'); "
            + "  result[i] = token;"
            + "end "
            + "return result;";

    private static final String DEL_TOKEN_SCRIPT = ""
            + "local token = ARGV[1]; "
            + "redis.call('EXPIRE','at:'..token, 0); ";

    public static Object runScript(ScriptType scriptType, List<String> keys, List<String> args) {
        Object result;
        JedisSentinelPool pool = RedisConnector.getPool();
        if (pool == null) {
            return null;
        }
        Jedis jedis = pool.getResource();

        try {
            result = jedis.evalsha(getScriptSHA(scriptType), keys, args);
        } catch (JedisDataException e) {
            String sha = jedis.scriptLoad(getScript(scriptType));
            setScriptSHA(scriptType, sha);
            result = jedis.evalsha(getScriptSHA(scriptType), keys, args);
        }

        jedis.close();
        return result;
    }

    private static Map<ScriptType, String> scriptCache = new ConcurrentHashMap<ScriptType, String>();

    private static String getScriptSHA(ScriptType scriptType) {
        return scriptCache.get(scriptType);
    }

    private static void setScriptSHA(ScriptType scriptType, String sha) {
        scriptCache.put(scriptType, sha);
    }

    private static String getScript(ScriptType scriptType) {
        switch (scriptType) {
        case STORE_CLIENT_CREDENTIALS:
            return STORE_CLIENT_CREDENTIALS_SCRIPT;
        case STORE_SCOPE:
            return STORE_SCOPE_SCRIPT;
        case FIND_SCOPE:
            return FIND_SCOPE_SCRIPT;
        case GET_ALL_SCOPES:
            return GET_ALL_SCOPES_SCRIPT;
        case DEL_SCOPE:
            return DEL_SCOPE_SCRIPT;
        case GET_ALL_APPS:
            return GET_ALL_APPS_SCRIPT;
        case GET_CLIENT_CREDENTIALS:
            return GET_CLIENT_CREDENTIALS_SCRIPT;
        case UPDATE_APPLICATION:
            return UPDATE_APPLICATION_SCRIPT;
        case STORE_ACCESS_TOKEN:
            return STORE_ACCESS_TOKEN_SCRIPT;
        case FIND_ACCESS_TOKEN:
            return FIND_ACCESS_TOKEN_SCRIPT;
        case STORE_AUTH_CODE:
            return STORE_AUTH_CODE_SCRIPT;
        case UPDATE_AUTH_CODE_STATUS:
            return UPDATE_AUTH_CODE_STATUS_SCRIPT;
        case ACCESS_TOKEN_BY_REFRESH_TOKEN:
            return ACCESS_TOKEN_BY_REFRESH_TOKEN_SCRIPT;
        case UPDATE_ACCESS_TOKEN_STATUS:
            return UPDATE_ACCESS_TOKEN_STATUS_SCRIPT;
        case FIND_AUTH_CODE:
            return FIND_AUTH_CODE_SCRIPT;
        case GET_AT_BY_USER_AND_APP:
            return GET_AT_BY_USER_AND_APP_SCRIPT;
        case DEL_TOKEN:
            return DEL_TOKEN_SCRIPT;
        default:
            throw new InvalidParameterException("Script " + scriptType + " cannot be found!");

        }
    }
}
