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

import static org.testng.Assert.assertTrue;

import org.testng.annotations.Test;

/**
 * @author Rossitsa Borissova
 */
public class DBManagerFactoryTest {


    @Test
    public void when_no_oauth20_database_set_return_mongodb() throws Exception {
        // GIVEN
        String path = getClass().getClassLoader().getResource("apifest-oauth-test.properties").getPath();
        System.setProperty("properties.file", path);
        OAuthServer.loadConfig();

        // WHEN
        DBManager dbManager = DBManagerFactory.getInstance();

        // THEN
        assertTrue(dbManager instanceof MongoDBManager);
        System.setProperty("properties.file", "");
    }
}
