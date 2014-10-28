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
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Date;

import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.annotate.JsonPropertyOrder;
import org.codehaus.jackson.map.annotate.JsonSerialize;
import org.codehaus.jackson.map.annotate.JsonSerialize.Inclusion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Contains info about client application.
 *
 * @author Rossitsa Borissova
 */
@JsonPropertyOrder({ "name", "description", "client_id", "client_secret", "scope", "registered", "redirect_uri", "status"})
@JsonSerialize(include = Inclusion.NON_EMPTY)
public class ApplicationInfo implements Serializable {

    protected static Logger log = LoggerFactory.getLogger(ApplicationInfo.class);

    private static final long serialVersionUID = 6017283924235608024L;

    @JsonProperty("redirect_uri")
    private String redirectUri;

    @JsonProperty("registered")
    private Date registered;

    @JsonProperty("scope")
    private String scope;

    @JsonProperty("description")
    private String description;

    @JsonProperty("name")
    private String name;

    @JsonProperty("status")
    private Integer status;

    @JsonProperty("client_id")
    private String id = "";

    @JsonProperty("client_secret")
    private String secret = "";

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

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public Integer getStatus() {
        return status;
    }

    public void setStatus(Integer status) {
        this.status = status;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public boolean valid() {
        boolean valid = false;
        if (name != null && name.length() > 0 && scope != null && scope.length() > 0 &&
                redirectUri != null && redirectUri.length() > 0) {

            try {
                new URL(redirectUri);
                valid = true;
            } catch (MalformedURLException e) {
                log.info("not valid URI {}", redirectUri);
            }
        }
        return valid;
    }

    public boolean validForUpdate() {
        boolean valid = false;
        if ((scope != null && !scope.isEmpty()) || (description != null && !description.isEmpty()) || status != null) {
           valid = true;
        }
        if (status != null && (status != ClientCredentials.ACTIVE_STATUS && status != ClientCredentials.INACTIVE_STATUS)) {
            valid = false;
        }
        return valid;
    }
}
