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

import com.apifest.oauth20.persistence.hazelcast.HazelcastDBManager;

public class DBManagerFactory {

    protected static DBManager dbManager;

    // TODO: make H2 DB default
    public static DBManager getInstance() {
        if (dbManager == null) {
            if ("redis".equalsIgnoreCase(OAuthServer.getDatabase())) {
                dbManager = new RedisDBManager();
                ((RedisDBManager) dbManager).setupDBManager();
            }
            if ("mongodb".equalsIgnoreCase(OAuthServer.getDatabase())) {
                dbManager = new MongoDBManager();
            }
            if ("hazelcast".equalsIgnoreCase(OAuthServer.getDatabase())) {
                dbManager = new HazelcastDBManager();
            }
        }
        return dbManager;
    }

    public static void init() {
        // that will instantiate a connection to the storage
        getInstance();
    }
}
