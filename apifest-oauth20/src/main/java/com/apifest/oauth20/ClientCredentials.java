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
import java.util.Map;

import org.codehaus.jackson.annotate.JsonIgnore;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.annotate.JsonPropertyOrder;

/**
 * Holds client application credentials - client_id and client_secret.
 *
 * @author Rossitsa Borissova
 */
@JsonPropertyOrder({ "client_id", "client_secret" })
public class ClientCredentials implements Serializable {

    private static final long serialVersionUID = 6443754960051591393L;

    public static final int ACTIVE_STATUS = 1;
    public static final int INACTIVE_STATUS = 0;

    @JsonProperty("client_id")
    private String id = "";

    @JsonProperty("client_secret")
    private String secret = "";

    // scopes are separated by space
    @JsonIgnore
    private String scope = "";

    @JsonIgnore
    private String name = "";

    @JsonIgnore
    private Long created;

    @JsonIgnore
    private String uri = "";

    @JsonIgnore
    private String descr = "";

    // client types - public or confidential
    @JsonIgnore
    private int type;

    // 1 - active, 0 - not active
    @JsonIgnore
    private int status;

    public ClientCredentials(String appName, String scope, String description, String uri) {
        this.name = appName;
        this.scope = scope;
        this.descr = (description != null)? description : "";
        this.uri = uri;
        this.id = generateClientId();
        this.secret = generateClientSecret();
        this.created = (new Date()).getTime();
        this.status = INACTIVE_STATUS;
    }

    public ClientCredentials(String appName, String scope, String description, String uri, String clientId, String clientSecret) {
        this.name = appName;
        this.scope = scope;
        this.descr = (description != null)? description : "";
        this.uri = uri;
        this.id = clientId;
        this.secret = clientSecret;
        this.created = (new Date()).getTime();
        this.status = INACTIVE_STATUS;
    }

    public ClientCredentials() {

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

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getUri() {
        return uri;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }

    public String getDescr() {
        return descr;
    }

    public void setDescr(String descr) {
        this.descr = descr;
    }

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public Long getCreated() {
        return created;
    }

    public void setCreated(Long created) {
        this.created = created;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    private String generateClientId() {
        return RandomGenerator.generateShortRandomString();
    }

    private String generateClientSecret() {
        return RandomGenerator.generateRandomString();
    }

    /**
     * Used to create an instance when a record from DB is loaded.
     *
     * @param map
     *            Map that contains the record info
     * @return instance of ClientCredentials
     */
    public static ClientCredentials loadFromMap(Map<String, Object> map) {
        ClientCredentials creds = new ClientCredentials();
        creds.name = (String) map.get("name");
        creds.id = (String) map.get("_id");
        creds.secret = (String) map.get("secret");
        creds.uri = (String) map.get("uri");
        creds.descr = (String) map.get("descr");
        creds.type = ((Number) map.get("type")).intValue();
        creds.status = ((Number) map.get("status")).intValue();
        creds.created = (Long) map.get("created");
        creds.scope = (String) map.get("scope");
        return creds;
    }

    public static ClientCredentials loadFromStringMap(Map<String, String> map) {
        ClientCredentials creds = new ClientCredentials();
        creds.name = map.get("name");
        creds.id = map.get("_id");
        creds.secret = map.get("secret");
        creds.uri = map.get("uri");
        creds.descr = map.get("descr");
        creds.type = Integer.valueOf(map.get("type"));
        creds.status = Integer.valueOf(map.get("status"));
        creds.created = Long.valueOf(map.get("created"));
        creds.scope = map.get("scope");
        return creds;
    }

}
