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
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.testng.annotations.Test;

/**
 * @author Rossitsa Borissova
 */
public class ScopeTest {

    @Test
    public void when_scope_name_length_less_than_2_validate_return_false() throws Exception {
        // GIVEN
        Scope scope = new Scope();
        scope.setScope("");
        scope.setDescription("some descr");
        scope.setCcExpiresIn(200);
        scope.setPassExpiresIn(100);

        // WHEN
        boolean valid = scope.valid();

        // THEN
        assertFalse(valid);
    }

    @Test
    public void when_scope_null_return_false() throws Exception {
        // GIVEN
        Scope scope = new Scope();
        scope.setScope(null);
        scope.setDescription("some descr");
        scope.setCcExpiresIn(200);
        scope.setPassExpiresIn(100);

        // WHEN
        boolean valid = scope.valid();

        // THEN
        assertFalse(valid);
    }

    @Test
    public void when_description_null_return_false() throws Exception {
        // GIVEN
        Scope scope = new Scope();
        scope.setScope("basic");
        scope.setDescription(null);
        scope.setCcExpiresIn(200);
        scope.setPassExpiresIn(100);

        // WHEN
        boolean valid = scope.valid();

        // THEN
        assertFalse(valid);
    }

    @Test
    public void when_cc_expiresIn_0_return_false() throws Exception {
        // GIVEN
        Scope scope = new Scope();
        scope.setScope("basic");
        scope.setDescription("some description");
        scope.setCcExpiresIn(0);
        scope.setPassExpiresIn(100);

        // WHEN
        boolean valid = scope.valid();

        // THEN
        assertFalse(valid);
    }

    @Test
    public void when_pass_expiresIn_0_return_false() throws Exception {
        // GIVEN
        Scope scope = new Scope();
        scope.setScope("basic");
        scope.setDescription("some description");
        scope.setCcExpiresIn(100);
        scope.setPassExpiresIn(0);

        // WHEN
        boolean valid = scope.valid();

        // THEN
        assertFalse(valid);
    }

    @Test
    public void when_refresh_expiresIn_0_return_false() throws Exception {
        // GIVEN
        Scope scope = new Scope();
        scope.setScope("basic");
        scope.setDescription("some description");
        scope.setCcExpiresIn(300);
        scope.setPassExpiresIn(100);
        scope.setRefreshExpiresIn(0);

        // WHEN
        boolean valid = scope.valid();

        // THEN
        assertFalse(valid);
    }

    @Test
    public void when_refresh_expiresIn_null_and_pass_ExpiresIn_valid_return_true() throws Exception {
        // GIVEN
        Scope scope = new Scope();
        scope.setScope("basic");
        scope.setDescription("some description");
        scope.setCcExpiresIn(300);
        scope.setPassExpiresIn(100);

        // WHEN
        boolean valid = scope.valid();

        // THEN
        assertTrue(valid);
    }

    @Test
    public void when_all_fields_valid_return_true() throws Exception {
        // GIVEN
        Scope scope = new Scope();
        scope.setScope("basic");
        scope.setDescription("some description");
        scope.setCcExpiresIn(300);
        scope.setPassExpiresIn(100);

        // WHEN
        boolean valid = scope.valid();

        // THEN
        assertTrue(valid);
    }

    @Test
    public void when_load_from_map_return_scope_with_initialized_fields() throws Exception {
        // GIVEN
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("_id", "basic");
        map.put(Scope.DESCRIPTION_FIELD, "some descr");
        map.put(Scope.CC_EXPIRES_IN_FIELD, 300);

        // WHEN
        Scope scope = Scope.loadFromMap(map);

        // THEN
        assertEquals(scope.getScope(), "basic");
        assertEquals(scope.getDescription(), "some descr");
        assertEquals(scope.getCcExpiresIn(), Integer.valueOf(300));
    }

    @Test
    public void when_load_from_string_map_return_scope_with_initialized_fields() throws Exception {
        // GIVEN
        Map<String, String> map = new HashMap<String, String>();
        map.put("id", "basic");
        map.put(Scope.DESCRIPTION_FIELD, "some descr");
        map.put(Scope.CC_EXPIRES_IN_FIELD, "300");
        map.put(Scope.PASS_EXPIRES_IN_FIELD, "100");

        // WHEN
        Scope scope = Scope.loadFromStringMap(map);

        // THEN
        assertEquals(scope.getScope(), "basic");
        assertEquals(scope.getDescription(), "some descr");
        assertEquals(scope.getCcExpiresIn(), Integer.valueOf(300));
    }

    @Test
    public void when_scope_name_contains_not_alphaNumeric_return_false() throws Exception {
        boolean valid = Scope.validScopeName("basic@es");

        // THEN
        assertFalse(valid);
    }

    @Test
    public void when_scope_name_contains_space_return_false() throws Exception {
        boolean valid = Scope.validScopeName("basic my");

        // THEN
        assertFalse(valid);
    }

    @Test
    public void when_scope_name_contains_dash_return_true() throws Exception {
        boolean valid = Scope.validScopeName("my-basic");

        // THEN
        assertTrue(valid);
    }

    @Test
    public void when_scope_name_contains_several_dashes_return_true() throws Exception {
        boolean valid = Scope.validScopeName("my-basic-scope");

        // THEN
        assertTrue(valid);
    }

    @Test
    public void when_scope_name_contains_dash_and_undescore_return_true() throws Exception {
        boolean valid = Scope.validScopeName("my-basic_scope");

        // THEN
        assertTrue(valid);
    }

    @Test
    public void when_scope_name_contains_several_undescores_return_true() throws Exception {
        boolean valid = Scope.validScopeName("my_basic_scope");

        // THEN
        assertTrue(valid);
    }

    @Test
    public void when_refreshExpiresIn_valid_then_valid_for_update_return_true() throws Exception {
        // GIVEN
        Scope scope = new Scope();
        scope.setRefreshExpiresIn(10);

        // WHEN
        boolean valid = scope.validForUpdate();

        // THEN
        assertTrue(valid);
    }

    @Test
    public void when_passExpiresIn_valid_then_valid_for_update_return_true() throws Exception {
        // GIVEN
        Scope scope = new Scope();
        scope.setPassExpiresIn(5);

        // WHEN
        boolean valid = scope.validForUpdate();

        // THEN
        assertTrue(valid);
    }

    @Test
    public void when_no_mandatory_field_then_valid_for_update_return_false() throws Exception {
        // GIVEN
        Scope scope = new Scope();
        scope.setScope("name");

        // WHEN
        boolean valid = scope.validForUpdate();

        // THEN
        assertFalse(valid);
    }

    @Test
    public void when_check_valid_with_no_refresh_expires_in_set_refresh_expires_in_to_pass_expires_in() throws Exception {
        // GIVEN
        Scope scope = new Scope();
        scope.setScope("name");
        scope.setPassExpiresIn(300);
        scope.setCcExpiresIn(300);
        scope.setDescription("descr");

        // WHEN
        boolean valid = scope.valid();

        // THEN
        assertTrue(scope.getRefreshExpiresIn() == scope.getPassExpiresIn());
        assertTrue(valid);
    }

    @Test
    public void when_check_valid_with_refresh_expires_in_set_keep_that_refresh_expires_in_value() throws Exception {
        // GIVEN
        Scope scope = new Scope();
        scope.setScope("name");
        scope.setPassExpiresIn(300);
        scope.setCcExpiresIn(300);
        scope.setRefreshExpiresIn(6000);
        scope.setDescription("descr");

        // WHEN
        boolean valid = scope.valid();

        // THEN
        assertTrue(scope.getRefreshExpiresIn() == 6000);
        assertTrue(valid);
    }

    @Test
    public void when_load_from_map_without_refresh_expires_in_use_pass_expires_in() throws Exception {
        // GIVEN
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("_id", "basic");
        map.put(Scope.DESCRIPTION_FIELD, "some descr");
        map.put(Scope.CC_EXPIRES_IN_FIELD, 1800);
        map.put(Scope.PASS_EXPIRES_IN_FIELD, 300);

        // WHEN
        Scope scope = Scope.loadFromMap(map);

        // THEN
        assertTrue(scope.getRefreshExpiresIn() == 300);
    }

    @Test
    public void when_load_from_string_map_without_refresh_expires_in_use_pass_expires_in() throws Exception {
        // GIVEN
        Map<String, String> map = new HashMap<String, String>();
        map.put("_id", "basic");
        map.put(Scope.DESCRIPTION_FIELD, "some descr");
        map.put(Scope.CC_EXPIRES_IN_FIELD, "1800");
        map.put(Scope.PASS_EXPIRES_IN_FIELD, "300");

        // WHEN
        Scope scope = Scope.loadFromStringMap(map);

        // THEN
        assertTrue(scope.getRefreshExpiresIn() == 300);
    }
}
