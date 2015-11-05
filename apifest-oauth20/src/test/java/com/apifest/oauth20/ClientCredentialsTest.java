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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.testng.annotations.Test;

/**
 * @author Rossitsa Borissova
 */
public class ClientCredentialsTest {

    @Test
    public void when_map_load_class_from_it() throws Exception {
        // GIVEN
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("name", "Test App");
        map.put("_id", "763273054098803");
        map.put("secret", "2475a03c2da45c5427c25747ab80b2e1");
        map.put("created", 1365191565324l);
        map.put("type", 1);
        map.put("status", 1);
        map.put("applicationDetails", "{\"my\":\"param\"}");

        // WHEN
        ClientCredentials creds = ClientCredentials.loadFromMap(map);

        // THEN
        assertEquals(creds.getName(), "Test App");
        assertTrue(creds.getCreated().longValue() == 1365191565324l);
    }

    @Test
    public void when_construct_generate_client_id_and_client_secret() throws Exception {
        // WHEN
        ClientCredentials creds = new ClientCredentials("Demo", "basic", "descr", "http://example.com", null);

        // THEN
        assertNotNull(creds.getId());
        assertNotNull(creds.getSecret());
    }

    @Test
    public void when_construct_set_date() throws Exception {
        // WHEN
        ClientCredentials creds = new ClientCredentials("Demo", "basic", "descr", "http://example.com", null);

        // THEN
        assertNotNull(creds.getCreated());
    }

    @Test
    public void when_no_application_details_loadFromMap_should_not_throw_exception() throws Exception {
        // GIVEN
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("name", "Test App");
        map.put("_id", "763273054098803");
        map.put("secret", "2475a03c2da45c5427c25747ab80b2e1");
        map.put("created", 1365191565324l);
        map.put("type", 1);
        map.put("status", 1);

        // WHEN
        ClientCredentials creds = ClientCredentials.loadFromMap(map);

        // THEN
        assertNull(creds.getApplicationDetails());
    }


    @Test
    public void when_no_application_details_loadFromStringMap_should_not_throw_exception() throws Exception {
        // GIVEN
        Map<String, String> map = new HashMap<String, String>();
        map.put("name", "Test App");
        map.put("_id", "763273054098803");
        map.put("secret", "2475a03c2da45c5427c25747ab80b2e1");
        map.put("created", "1365191565324");
        map.put("type", "1");
        map.put("status", "1");

        // WHEN
        ClientCredentials creds = ClientCredentials.loadFromStringMap(map);

        // THEN
        assertNull(creds.getApplicationDetails());
    }

}
