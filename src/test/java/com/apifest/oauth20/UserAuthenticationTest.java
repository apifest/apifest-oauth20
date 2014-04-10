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

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.testng.Assert.assertEquals;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.entity.StringEntity;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * @author Rossitsa Borissova
 */
public class UserAuthenticationTest {

    UserAuthentication auth;

    @BeforeMethod
    public void setup() {
        auth = spy(new UserAuthentication());
    }

    @Test
    public void when_response_entity_read_it_to_string() throws Exception {
        // GIVEN
        HttpResponse response = mock(HttpResponse.class);
        HttpEntity entity = new StringEntity("this is the response");
        given(response.getEntity()).willReturn(entity);

        // WHEN
        String str = auth.readResponse(response);

        // THEN
        assertEquals(str.trim(), "this is the response");
    }
}
