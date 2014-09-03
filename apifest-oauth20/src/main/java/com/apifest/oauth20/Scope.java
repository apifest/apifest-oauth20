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
@JsonPropertyOrder({ "name", "description", "cc_expires_in", "pass_expires_in"})
public class Scope {

    static final String SCOPE_FIELD = "scope";
    static final String DESCRIPTION_FIELD = "description";
    static final String CC_EXPIRES_IN_FIELD = "ccExpiresIn";
    static final String PASS_EXPIRES_IN_FIELD = "passExpiresIn";

    private static final String SPACE = " ";

    @JsonProperty("scope")
    private String scope;

    @JsonProperty("description")
    private String description;

    @JsonProperty("cc_expires_in")
    private Integer ccExpiresIn;

    @JsonProperty("pass_expires_in")
    private Integer passExpiresIn;

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

    public Integer getCcExpiresIn() {
        return ccExpiresIn;
    }

    public void setCcExpiresIn(Integer ccExpiresIn) {
        this.ccExpiresIn = ccExpiresIn;
    }

    public Integer getPassExpiresIn() {
        return passExpiresIn;
    }

    public void setPassExpiresIn(int passExpiresIn) {
        this.passExpiresIn = passExpiresIn;
    }

    public static Scope loadFromMap(Map<String, Object> map) {
        Scope scope = new Scope();
        scope.scope = (String) map.get("_id");
        scope.description = (String) map.get(DESCRIPTION_FIELD);
        scope.ccExpiresIn = (Integer) map.get(CC_EXPIRES_IN_FIELD);
        scope.passExpiresIn = (Integer) map.get(PASS_EXPIRES_IN_FIELD);
        return scope;
    }

    public static Scope loadFromStringMap(Map<String, String> map) {
        Scope scope = new Scope();
        scope.scope = map.get("id");
        scope.description = map.get(DESCRIPTION_FIELD);
        scope.ccExpiresIn = Integer.valueOf(map.get(CC_EXPIRES_IN_FIELD));
        scope.passExpiresIn = Integer.valueOf(map.get(PASS_EXPIRES_IN_FIELD));
        return scope;
    }

    public boolean valid() {
        boolean validScope = scope != null && scope.length() >= 2;
        boolean validCCExpiresIn = ccExpiresIn != null && ccExpiresIn > 0;
        boolean validPassExpiresIn = passExpiresIn != null && passExpiresIn > 0;
        if (!validScope || description == null || !validCCExpiresIn || !validPassExpiresIn) {
            return false;
        }
        return true;
    }

    public boolean validForUpdate() {
        boolean valid = false;
        boolean validCCExpiresIn = ccExpiresIn != null && ccExpiresIn > 0;
        boolean validPassExpiresIn = passExpiresIn != null && passExpiresIn > 0;
        if ((scope != null && scope.length() > 0) &&
                ((description != null && description.length() > 0) || validCCExpiresIn || validPassExpiresIn)) {
           valid = true;
        }
        return valid;
    }

    public static boolean validScopeName(String scopeName) {
        if (scopeName.contains(SPACE)) {
            return false;
        }
        return true;
    }
}
