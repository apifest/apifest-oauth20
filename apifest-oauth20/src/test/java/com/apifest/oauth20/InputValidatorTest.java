/*
 * Copyright 2013-2015, ApiFest project
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

import static org.mockito.BDDMockito.willDoNothing;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.verify;

import java.io.ByteArrayInputStream;

import org.jboss.netty.util.CharsetUtil;
import org.testng.annotations.Test;

/**
 * @author Rossitsa Borissova
 *
 */
public class InputValidatorTest {


    @Test
    public void when_scope_input_invoke_validate_method_of_scope_validator_class() throws Exception {
        // GIVEN
        MockScopeValidator.install();
        willDoNothing().given(JsonInputValidatorFactory.getValidator(Scope.class)).validate(anyString(), anyString());

        String inputValue = "300";

        String testString = "{\"" + Scope.JSON_CC_EXPIRES_IN + "\":\"" + inputValue + "\"}";

        // WHEN
        InputValidator.validate(new ByteArrayInputStream(testString.getBytes(CharsetUtil.UTF_8)), Scope.class);

        // THEN
        verify(ScopeValidator.getInstance()).validate(Scope.JSON_CC_EXPIRES_IN, inputValue);
        MockScopeValidator.deinstall();
    }

    @Test
    public void when_application_info_input_invoke_validate_method_of_application_info_validator_class() throws Exception {
        // GIVEN
        MockApplicationInfoValidator.install();
        willDoNothing().given(JsonInputValidatorFactory.getValidator(ApplicationInfo.class)).validate(anyString(), anyString());

        String inputValue = "1";

        // WHEN
        String testString = "{\"" + ApplicationInfo.JSON_STATUS + "\":\"" + inputValue + "\"}";
        InputValidator.validate(new ByteArrayInputStream(testString.getBytes(CharsetUtil.UTF_8)), ApplicationInfo.class);

        // THEN
        verify(ApplicationInfoValidator.getInstance()).validate(ApplicationInfo.JSON_STATUS, inputValue);
        MockApplicationInfoValidator.deinstall();
    }

    @Test
    public void when_no_validator_do_not_throw_NPE() throws Exception {

        // WHEN
        String testString = "{\"client_id\":\"123456\"}";
        InputValidator.validate(new ByteArrayInputStream(testString.getBytes(CharsetUtil.UTF_8)), ClientCredentials.class);
    }
}
