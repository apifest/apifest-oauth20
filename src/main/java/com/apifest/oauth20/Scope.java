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

import java.util.Map;

import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.annotate.JsonPropertyOrder;

/**
 * Represents an OAuth20 scope.
 *
 * @author Rossitsa Borissova
 */
@JsonPropertyOrder({"name","description","expires_in"})
public class Scope {

    static final String SCOPE_FIELD = "scope";
    static final String DESCRIPTION_FIELD = "description";
    static final String EXPIRES_IN_FIELD = "expiresIn";

    @JsonProperty("scope")
    private String scope;

    @JsonProperty("description")
    private String description;

    @JsonProperty("expires_in")
    private Integer expiresIn;

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Integer getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(int expiresIn) {
        this.expiresIn = expiresIn;
    }

    public static Scope loadFromMap(Map<String, Object> map) {
        Scope scope = new Scope();
        scope.scope = (String) map.get("_id");
        scope.description = (String) map.get(DESCRIPTION_FIELD);
        scope.expiresIn = (Integer) map.get(EXPIRES_IN_FIELD);
        return scope;
    }

    public boolean validate() {
        if((scope == null && scope.length() >= 2) ||
                 description == null ||
                (expiresIn == null && expiresIn > 0)) {
            return false;
        }
        return true;
    }
}
