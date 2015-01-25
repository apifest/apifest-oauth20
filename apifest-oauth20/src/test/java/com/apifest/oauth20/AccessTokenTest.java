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

import static org.mockito.BDDMockito.willReturn;
import static org.mockito.Mockito.spy;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.codehaus.jackson.map.ObjectMapper;
import org.testng.annotations.Test;

/**
 * @author Rossitsa Borissova
 */
public class AccessTokenTest {

    @Test
    @SuppressWarnings("unchecked")
    public void when_load_from_map_initialize_all_fields() throws Exception {
        // GIVEN
        String jsonStr = "{\"_id\" : \"51619e3182abb4b7b7e06d4a\", \"valid\" : true, \"scope\" : null, \"clientId\" : \"767316324475102\", "
                + "\"token\" : \"2a6ceee879e57fb7ef879b8be96db0c72c1ef3e42bb0e2f9746200b85edafb3c\", "
                + "\"expiresIn\" : \"599\", \"userId\" : \"12345\", \"codeId\" : \"mvmxEVdjqdFr##yFdxnliZ#vTBOcsR#QGMGxa-dqGU-Z#PZjkojc_YCshPa_bvQc"
                + "pmH=cq-ZGNeEzlTqxCteijq-_UBPnF=kVdsJEe=WUYWg_ptHp-VmrmelqWnfRMdolV=ibwJPMdLxkIriCEYFt#fGNzlLpgzzyT-Hoz#tkwWUGhZHuzOiruiafxOKScuaW=hYkICr\", "
                + "\"refreshToken\" : \"197ef958a30828c2148a1f242502a9473e5de0e6e5abfb55641e972fc32850e0\", \"type\" : \"Bearer\"}";

        Map<String, Object> map = new ObjectMapper().readValue(jsonStr, Map.class);
        map.put("created", 1365351985645l);

        // WHEN
        AccessToken accessToken = AccessToken.loadFromMap(map);

        // THEN
        assertEquals(accessToken.getClientId(), "767316324475102");
        assertEquals(
                accessToken.getCodeId(),
                "mvmxEVdjqdFr##yFdxnliZ#vTBOcsR#QGMGxa-dqGU-Z#PZjkojc_YCshPa_bvQcpmH=cq-ZGNeEzlTqxCteijq-_UBPnF=kVdsJEe=WUYWg_ptHp-VmrmelqWnfRMdolV=ibwJPMdLxkIriCEYFt#fGNzlLpgzzyT-Hoz#tkwWUGhZHuzOiruiafxOKScuaW=hYkICr");
        assertTrue(accessToken.getCreated() == 1365351985645l);
        assertEquals(accessToken.getExpiresIn(), "599");
        assertEquals(accessToken.getRefreshToken(),
                "197ef958a30828c2148a1f242502a9473e5de0e6e5abfb55641e972fc32850e0");
        assertEquals(accessToken.getScope(), null);
        assertEquals(accessToken.getToken(),
                "2a6ceee879e57fb7ef879b8be96db0c72c1ef3e42bb0e2f9746200b85edafb3c");
        assertEquals(accessToken.getType(), "Bearer");
        assertEquals(accessToken.getUserId(), "12345");
        assertEquals(accessToken.isValid(), true);
    }

    @Test
    public void when_create_access_token_add_refresh_token() throws Exception {
        // WHEN
        AccessToken accessToken = new AccessToken("Bearer", "599", "basic", "1800");

        // THEN
        assertNotNull(accessToken.getRefreshToken());
    }

    @Test
    public void when_create_access_token_for_client_credentials_do_not_add_refresh_token()
            throws Exception {
        // WHEN
        AccessToken accessToken = new AccessToken("Bearer", "599", "basic", false, "1800");

        // THEN
        assert ("".equals(accessToken.getRefreshToken()));
    }

    @Test
    public void when_created_plus_expiresIn_greater_then_current_time_return_true()
            throws Exception {
        // GIVEN
        AccessToken accessToken = spy(new AccessToken("Bearer", "899", "basic", false, "1800"));
        Calendar cal = Calendar.getInstance();
        cal.setTime(new Date(System.currentTimeMillis()));
        cal.add(Calendar.MINUTE, -16);
        Long created = cal.getTimeInMillis();
        willReturn(created).given(accessToken).getCreated();
        willReturn("899").given(accessToken).getExpiresIn();

        // WHEN
        boolean expired = accessToken.tokenExpired();

        // THEN
        assertTrue(expired);
    }

    @Test
    public void when_created_plus_expiresIn_less_then_current_time_return_false() throws Exception {
        // GIVEN
        AccessToken accessToken = spy(new AccessToken("Bearer", "899", "basic", false, "1800"));
        Calendar cal = Calendar.getInstance();
        cal.setTime(new Date(System.currentTimeMillis()));
        cal.add(Calendar.MINUTE, -14);
        Long created = cal.getTimeInMillis();
        willReturn(created).given(accessToken).getCreated();
        willReturn("899").given(accessToken).getExpiresIn();

        // WHEN
        boolean expired = accessToken.tokenExpired();

        // THEN
        assertFalse(expired);
    }

    @Test
    public void when_refresh_token_duration_less_than_now_return_false() throws Exception {
        // GIVEN
        AccessToken accessToken = spy(new AccessToken("Bearer", "300", "basic", true, "1800"));
        Calendar cal = Calendar.getInstance();
        cal.setTime(new Date(System.currentTimeMillis()));
        cal.add(Calendar.MINUTE, -5);
        Long created = cal.getTimeInMillis();
        willReturn(created).given(accessToken).getCreated();

        // WHEN
        boolean expired = accessToken.refreshTokenExpired();

        // THEN
        assertFalse(expired);
    }

    @Test
    public void when_refresh_token_duration_greater_than_now_return_true() throws Exception {
        // GIVEN
        AccessToken accessToken = spy(new AccessToken("Bearer", "300", "basic", true, "600"));
        Calendar cal = Calendar.getInstance();
        cal.setTime(new Date(System.currentTimeMillis()));
        cal.add(Calendar.MINUTE, -11);
        Long created = cal.getTimeInMillis();
        willReturn(created).given(accessToken).getCreated();

        // WHEN
        boolean expired = accessToken.refreshTokenExpired();

        // THEN
        assertTrue(expired);
    }

    @Test
    public void when_no_refresh_expires_in_set_it_to_expires_in() throws Exception {
        // WHEN
        AccessToken accessToken = new AccessToken("Bearer", "300", "basic", null);

        // THEN
       assertTrue(accessToken.getRefreshExpiresIn() == accessToken.getExpiresIn());
    }

    @Test
    public void when_no_refresh_expires_in_with_create_refresh_token_true_set_it_to_expires_in() throws Exception {
        // WHEN
        AccessToken accessToken = new AccessToken("Bearer", "300", "basic", true, null);

        // THEN
       assertTrue(accessToken.getRefreshExpiresIn() == accessToken.getExpiresIn());
    }

    @Test
    public void when_no_refresh_expires_in_with_predefined_refresh_token_true_set_it_to_expires_in() throws Exception {
        // WHEN
        AccessToken accessToken = new AccessToken("Bearer", "300", "basic", "refreshtoken", null);

        // THEN
       assertTrue(accessToken.getRefreshExpiresIn() == accessToken.getExpiresIn());
    }

    @Test
    public void when_refresh_expires_in_empty_with_predefined_refresh_token_true_set_it_to_expires_in() throws Exception {
        // WHEN
        AccessToken accessToken = new AccessToken("Bearer", "300", "basic", "refreshtoken", "");

        // THEN
       assertTrue(accessToken.getRefreshExpiresIn() == accessToken.getExpiresIn());
    }

    @Test
    public void when_refresh_expires_in_not_empty_with_predefined_refresh_token_true_use_that_value() throws Exception {
        // WHEN
        AccessToken accessToken = new AccessToken("Bearer", "300", "basic", "refreshtoken", "1800");

        // THEN
       assertTrue(accessToken.getRefreshExpiresIn() == "1800");
    }


    @Test
    public void load_access_token_from_string_map_without_refresh_expires_in() throws Exception {
        // GIVEN
        Map<String, String> map = new HashMap<String, String>();
        map.put("token", "60c7addaadabdada583950401f998c1df9ed6e4d5da637eb914a3dcbe0b3cff0");
        map.put("refreshToken", "b986032feac2475839ec0264c2a71b20609cabcc1ae15f8184f5538ff6f4d2bb");
        map.put("expiresIn", "300");
        map.put("type", "Bearer");
        map.put("scope", "basic");
        map.put("valid", "true");
        map.put("clientId", "b9db6d84dc98a895035e68f972e30503d3c724c8");
        map.put("codeId", "");
        map.put("userId", "3534543");
        map.put("created", "1421267589868");

        // WHEN
        AccessToken accessToken = AccessToken.loadFromStringMap(map);

        // THEN
        assertTrue(accessToken.getExpiresIn() == accessToken.getRefreshExpiresIn());
    }

    @Test
    public void load_access_token_from_map_without_refresh_expires_in() throws Exception {
        // GIVEN
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("token", "60c7addaadabdada583950401f998c1df9ed6e4d5da637eb914a3dcbe0b3cff0");
        map.put("refreshToken", "b986032feac2475839ec0264c2a71b20609cabcc1ae15f8184f5538ff6f4d2bb");
        map.put("expiresIn", "300");
        map.put("type", "Bearer");
        map.put("scope", "basic");
        map.put("valid", true);
        map.put("clientId", "b9db6d84dc98a895035e68f972e30503d3c724c8");
        map.put("codeId", "");
        map.put("userId", "3534543");
        map.put("created", 1421267589868L);

        // WHEN
        AccessToken accessToken = AccessToken.loadFromMap(map);

        // THEN
        assertTrue(accessToken.getExpiresIn() == accessToken.getRefreshExpiresIn());
    }

    @Test
    public void when_client_credentials_token_do_not_add_refresh_expires_in() throws Exception {
        // WHEN
        AccessToken accessToken = new AccessToken("Bearer", "1800", "scope", false, "600");

        // THEN
        assertTrue(accessToken.getRefreshExpiresIn().isEmpty());
    }

    @Test
    public void when_password_token_add_refresh_expires_in() throws Exception {
        // WHEN
        AccessToken accessToken = new AccessToken("Bearer", "300", "scope", true, "600");

        // THEN
        assertTrue(accessToken.getRefreshExpiresIn().equals("600"));
    }
}
