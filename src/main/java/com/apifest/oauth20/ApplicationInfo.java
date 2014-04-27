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

import java.io.Serializable;
import java.util.Date;

import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.annotate.JsonPropertyOrder;
import org.codehaus.jackson.map.annotate.JsonSerialize;
import org.codehaus.jackson.map.annotate.JsonSerialize.Inclusion;

/**
 * Contains info about client application.
 *
 * @author Rossitsa Borissova
 */
@JsonPropertyOrder({ "name", "description", "scope", "registered" })
@JsonSerialize(include = Inclusion.NON_NULL)
public class ApplicationInfo implements Serializable {

    private static final long serialVersionUID = -7602871956157070263L;

    @JsonProperty("registered")
    private Date registered;

    @JsonProperty("scope")
    private String scope;

    @JsonProperty("description")
    private String description;

    @JsonProperty("name")
    private String name;

    public String getRegistered() {
        return registered.toString();
    }

    public void setRegistered(Date registered) {
        this.registered = registered;
    }

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

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

}
