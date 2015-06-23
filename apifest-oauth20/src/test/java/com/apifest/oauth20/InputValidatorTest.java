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

import static org.mockito.BDDMockito.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

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

        // WHEN
        InputValidator.validate("{\"" + Scope.JSON_CC_EXPIRES_IN + "\":\"" + inputValue + "\"}", Scope.class);

        // THEN
        verify(ScopeValidator.instance).validate(Scope.JSON_CC_EXPIRES_IN, inputValue);
        MockScopeValidator.deinstall();
    }

    @Test
    public void when_application_info_input_invoke_validate_method_of_application_info_validator_class() throws Exception {
        // GIVEN
        MockApplicationInfoValidator.install();
        willDoNothing().given(JsonInputValidatorFactory.getValidator(ApplicationInfo.class)).validate(anyString(), anyString());

        String inputValue = "1";

        // WHEN
        InputValidator.validate("{\"" + ApplicationInfo.JSON_STATUS + "\":\"" + inputValue + "\"}", ApplicationInfo.class);

        // THEN
        verify(ApplicationInfoValidator.instance).validate(ApplicationInfo.JSON_STATUS, inputValue);
        MockApplicationInfoValidator.deinstall();
    }
}
