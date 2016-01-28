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
import java.util.Map;

import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.annotate.JsonPropertyOrder;
import org.codehaus.jackson.map.annotate.JsonSerialize;
import org.codehaus.jackson.map.annotate.JsonSerialize.Inclusion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Contains info about a client application.
 * Used for client application representation.
 *
 * @author Rossitsa Borissova
 */
@JsonPropertyOrder({ "name", "description", "client_id", "client_secret", "scope", "registered", "redirect_uri", "status", "application_details" })
@JsonSerialize(include = Inclusion.NON_EMPTY)
public class ApplicationInfo implements Serializable {

    protected static Logger log = LoggerFactory.getLogger(ApplicationInfo.class);

    public static final String JSON_STATUS = "status";

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

    @JsonProperty("application_details")
    private Map<String, String> applicationDetails = null;

    @JsonProperty("client_secret")
    private String secret = "";

    public String getRegistered() {
        return (registered != null) ? registered.toString() : "";
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

    public Map<String, String> getApplicationDetails() {
        return applicationDetails;
    }

    public void setApplicationDetails(Map<String, String> applicationDetails) {
        this.applicationDetails = applicationDetails;
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
        if ((scope != null && !scope.isEmpty()) || (description != null && !description.isEmpty()) || (status != null) ||
                (applicationDetails != null)) {
           valid = true;
        }
        if (status != null && (status != ClientCredentials.ACTIVE_STATUS && status != ClientCredentials.INACTIVE_STATUS)) {
            valid = false;
        }
        return valid;
    }

    public static ApplicationInfo loadFromMap(Map<String, Object> map) {
        ApplicationInfo appInfo = new ApplicationInfo();
        appInfo.name = (String) map.get("name");
        appInfo.id = (String) map.get("_id");
        appInfo.secret = (String) map.get("secret");
        appInfo.redirectUri = (String) map.get("uri");
        appInfo.description = (String) map.get("descr");
        //appInfo.type = ((Integer) map.get("type")).intValue();
        appInfo.status = ((Integer) map.get("status")).intValue();
        appInfo.registered = new Date((Long) map.get("created"));
        appInfo.scope = (String) map.get("scope");
        if (map.get("applicationDetails") != null) {
            appInfo.applicationDetails = JsonUtils.convertStringToMap(map.get("applicationDetails").toString());
        }
        return appInfo;
    }

    public static ApplicationInfo loadFromStringMap(Map<String, String> map) {
        ApplicationInfo appInfo = new ApplicationInfo();
        appInfo.name = map.get("name");
        appInfo.id = map.get("_id");
        appInfo.secret = map.get("secret");
        appInfo.redirectUri = map.get("uri");
        appInfo.description = map.get("descr");
        // appInfo.type = Integer.valueOf(map.get("type"));
        appInfo.status = Integer.valueOf(map.get("status"));
        appInfo.registered = new Date(Long.valueOf(map.get("created")));
        appInfo.scope = map.get("scope");
        appInfo.applicationDetails = JsonUtils.convertStringToMap(map.get("details"));
        return appInfo;
    }

    public static ApplicationInfo loadFromClientCredentials(ClientCredentials creds) {
        ApplicationInfo appInfo = null;
        if (creds != null) {
            appInfo = new ApplicationInfo();
            appInfo.setName(creds.getName());
            appInfo.setDescription(creds.getDescr());
            appInfo.setId(creds.getId());
            appInfo.setSecret(creds.getSecret());
            appInfo.setScope(creds.getScope());
            appInfo.setRedirectUri(creds.getUri());
            appInfo.setRegistered(new Date(creds.getCreated()));
            appInfo.setStatus(creds.getStatus());
            appInfo.setApplicationDetails(creds.getApplicationDetails());
        }
        return appInfo;
    }
}
