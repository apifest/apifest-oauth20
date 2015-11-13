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

import java.io.IOException;
import java.io.InputStream;

import org.codehaus.jackson.JsonFactory;
import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.JsonParser;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.util.JsonParserDelegate;

/**
 * Validates a given input.
 *
 * @author Rossitsa Borissova
 *
 */
public class InputValidator {

    private static ObjectMapper mapper = new ObjectMapper();

    /**
     * Validates an input and returns an instance of a given class constructed from the input.
     * @param input the input to be validated
     * @param clazz the class to be used to create an instance from the input
     * @return an instance created from the input
     * @throws JsonParseException
     * @throws IOException
     */
    public static <T> T validate(InputStream input, final Class<T> clazz) throws JsonParseException, IOException {
        JsonFactory factory = mapper.getJsonFactory();
        JsonParser parser = null;
        T obj = null;
        parser = factory.createJsonParser(input);
        JsonParser parserWrapper = new JsonParserDelegate(parser) {

            @Override
            public String getText() throws IOException, JsonParseException {
                String str = delegate.getText();
                try {
                    JsonInputValidator validator = JsonInputValidatorFactory.getValidator(clazz);
                    if (validator != null) {
                        validator.validate(delegate.getCurrentName(), str);
                    }
                } catch (OAuthException e) {
                    throw new JsonValidationException(e.getMessage());
                }
                return str;
            }
        };
        obj = mapper.readValue(parserWrapper, clazz);
        return obj;
    }

}
