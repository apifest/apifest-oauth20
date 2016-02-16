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

import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.apifest.oauth20.OAuthServer;

import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.JedisSentinelPool;

public final class RedisConnector {
    private static final int MAX_CONNECTIONS = 30;
    public static final byte WHEN_EXHAUSTED_FAIL = 0;
    private static Set<String> sentinels;
    private static JedisSentinelPool pool;
    private static Logger logger = LoggerFactory.getLogger(RedisConnector.class);

    private RedisConnector() {}

    public static JedisSentinelPool getPool() {
        if (pool == null) {
            sentinels = new HashSet<String>();
            String[] sentinelsList = OAuthServer.getRedisSentinels().split(",");
            JedisPoolConfig poolConfig = new JedisPoolConfig();
            poolConfig.setMaxTotal(MAX_CONNECTIONS);
            poolConfig.setBlockWhenExhausted(false);
            for (String sentinel : sentinelsList) {
                sentinels.add(sentinel);
            }
            pool = new JedisSentinelPool(OAuthServer.getRedisMaster(), sentinels, poolConfig);
        }
        return pool;
    }
}

