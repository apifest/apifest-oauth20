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

import static org.testng.Assert.*;

import java.util.HashMap;

import org.testng.annotations.Test;

/**
 *
 * @author Rossitsa Borissova
 */
public class ApplicationInfoTest {

    @Test
    public void when_scope_not_null_valid_for_update_true() throws Exception {
        // GIVEN
        ApplicationInfo appInfo = new ApplicationInfo();
        appInfo.setScope("basic");

        // WHEN
        boolean result = appInfo.validForUpdate();

        // THEN
        assertTrue(result);
    }

    @Test
    public void when_scope_is_empty_valid_for_update_false() throws Exception {
        // GIVEN
        ApplicationInfo appInfo = new ApplicationInfo();
        appInfo.setScope("");

        // WHEN
        boolean result = appInfo.validForUpdate();

        // THEN
        assertFalse(result);
    }

    @Test
    public void when_scope_is_null_valid_for_update_false() throws Exception {
        // GIVEN
        ApplicationInfo appInfo = new ApplicationInfo();
        appInfo.setScope(null);

        // WHEN
        boolean result = appInfo.validForUpdate();

        // THEN
        assertFalse(result);
    }

    @Test
    public void when_description_not_null_valid_for_update_true() throws Exception {
        // GIVEN
        ApplicationInfo appInfo = new ApplicationInfo();
        appInfo.setDescription("some descr");

        // WHEN
        boolean result = appInfo.validForUpdate();

        // THEN
        assertTrue(result);
    }

    @Test
    public void when_description_is_empty_valid_for_update_false() throws Exception {
        // GIVEN
        ApplicationInfo appInfo = new ApplicationInfo();
        appInfo.setDescription("");

        // WHEN
        boolean result = appInfo.validForUpdate();

        // THEN
        assertFalse(result);
    }

    @Test
    public void when_description_is_null_valid_for_update_false() throws Exception {
        // GIVEN
        ApplicationInfo appInfo = new ApplicationInfo();
        appInfo.setDescription(null);

        // WHEN
        boolean result = appInfo.validForUpdate();

        // THEN
        assertFalse(result);
    }

    @Test
    public void when_description_is_null_and_scope_is_not_null_valid_for_update_true() throws Exception {
        // GIVEN
        ApplicationInfo appInfo = new ApplicationInfo();
        appInfo.setDescription(null);
        appInfo.setScope("basic");

        // WHEN
        boolean result = appInfo.validForUpdate();

        // THEN
        assertTrue(result);
    }

    @Test
    public void when_description_is_not_null_and_scope_is_null_valid_for_update_true() throws Exception {
        // GIVEN
        ApplicationInfo appInfo = new ApplicationInfo();
        appInfo.setDescription("some descr");
        appInfo.setScope(null);

        // WHEN
        boolean result = appInfo.validForUpdate();

        // THEN
        assertTrue(result);
    }

    @Test
    public void when_status_is_not_null_valid_for_update_true() throws Exception {
        // GIVEN
        ApplicationInfo appInfo = new ApplicationInfo();
        appInfo.setStatus(1);

        // WHEN
        boolean result = appInfo.validForUpdate();

        // THEN
        assertTrue(result);
    }

    @Test
    public void when_status_is_null_valid_for_update_false() throws Exception {
        // GIVEN
        ApplicationInfo appInfo = new ApplicationInfo();
        appInfo.setStatus(null);

        // WHEN
        boolean result = appInfo.validForUpdate();

        // THEN
        assertFalse(result);
    }

    @Test
    public void when_status_is_not_1_or_0_valid_for_update_false() throws Exception {
        // GIVEN
        ApplicationInfo appInfo = new ApplicationInfo();
        appInfo.setStatus(2);

        // WHEN
        boolean result = appInfo.validForUpdate();

        // THEN
        assertFalse(result);
    }

    @Test
    public void when_scope_descr_and_status_is_not_null_but_status_is_not_valid_return_false() throws Exception {
        // GIVEN
        ApplicationInfo appInfo = new ApplicationInfo();
        appInfo.setDescription("descr");
        appInfo.setScope("scope");
        appInfo.setStatus(3);

        // WHEN
        boolean result = appInfo.validForUpdate();

        // THEN
        assertFalse(result);
    }

    @Test
    public void when_scope_descr_and_status_is_active_return_true() throws Exception {
        // GIVEN
        ApplicationInfo appInfo = new ApplicationInfo();
        appInfo.setDescription("descr");
        appInfo.setScope("scope");
        appInfo.setStatus(ClientCredentials.ACTIVE_STATUS);

        // WHEN
        boolean result = appInfo.validForUpdate();

        // THEN
        assertTrue(result);
    }

    @Test
    public void when_only_application_details_valid_for_update_return_true() throws Exception {
        // GIVEN
        ApplicationInfo appInfo = new ApplicationInfo();
        appInfo.setApplicationDetails(new HashMap<String, String>());

        // WHEN
        boolean result = appInfo.validForUpdate();

        // THEN
        assertTrue(result);
    }
}
