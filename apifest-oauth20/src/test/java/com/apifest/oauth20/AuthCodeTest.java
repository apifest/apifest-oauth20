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

import org.bson.types.ObjectId;
import org.testng.annotations.Test;

/**
 * @author Rossitsa Borissova
 */
public class AuthCodeTest {

    @Test
    public void when_create_auth_code_set_time_created() throws Exception {
        // WHEN
        AuthCode authCode = new AuthCode(AuthCode.generate(), "023390937349048",
                "http://www.example.com", "xyz", "basic", "code", "12345");

        // THEN
        assertNotNull(authCode.getCreated());
    }

    @Test
    public void when_load_from_map_initialize_fields() throws Exception {
        // GIVEN
        long created = 1365191565324l;
        String userId = "12345";
        String code = "gRDDgk_s-YAwmtflviOqqn-bnciqLDjfILnPNIsWDtDLSxQpI-VHZp#ivH-D#qBY_TjrjqAyQrrPIc#"
                + "wFPCsHQAcYyts=evmjEZdGO=vvJi=cjZtzXPnUGDtjfas_LJfDvObigUunZhJPU=lCqJhwFCyMPNJbpkdZLSOowcaC"
                + "LIrkooiBIw_nYYeLkBxIFfkiRmlC-hT";
        String redirecUri = "http://example.com";
        String clientId = "023390937349048";
        String id = "51619e3182abb4b7b7e06d4a";

        Map<String, Object> map = new HashMap<String, Object>();
        map.put("scope", null);
        map.put("created", created);
        map.put("userId", userId);
        map.put("state", null);
        map.put("code", code);
        map.put("redirectUri", redirecUri);
        map.put("clientId", clientId);
        map.put("valid", true);
        map.put("_id", new ObjectId("51619e3182abb4b7b7e06d4a"));

        // WHEN
        AuthCode authCode = AuthCode.loadFromMap(map);

        // THEN
        assertNull(authCode.getScope());
        assertTrue(authCode.getCreated().longValue() == created);
        assertEquals(authCode.getUserId(), userId);
        assertNull(authCode.getState());
        assertEquals(authCode.getCode(), code);
        assertEquals(authCode.getRedirectUri(), redirecUri);
        assertEquals(authCode.getClientId(), clientId);
        assertEquals(authCode.getId(), id);
    }

}
