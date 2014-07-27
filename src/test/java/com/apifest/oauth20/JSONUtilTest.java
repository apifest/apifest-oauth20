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
import static org.testng.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.testng.annotations.Test;

/**
 * @author Rossitsa Borissova
 */
public class JSONUtilTest {

    @Test
    public void when_json_string_convert_to_list() throws Exception {
        // GIVEN
        String json = "[{\"name\":\"key1\",\"value\":\"value1\"},{\"name\":\"key2\",\"value\":\"value2\"}]";

        // WHEN
        List<NameValue> list = JSONUtils.convertStringToList(json);

        // THEN
        assertEquals(list.get(0).getName(), "key1");
    }

    @Test
    public void when_list_convert_to_json() throws Exception {
        // GIVEN
        List<NameValue> details = new ArrayList<NameValue>();
        details.add(new NameValue("key1", "value1"));
        details.add(new NameValue("key2", "value2"));

        // WHEN
        String json = JSONUtils.convertListToJSON(details);

        // THEN
        assertTrue(json.toString().contains("[{\"name\":\"key1\",\"value\":\"value1\"},{\"name\":\"key2\",\"value\":\"value2\"}]"));
    }
}
