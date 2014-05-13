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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.http.QueryStringDecoder;
import org.jboss.netty.util.CharsetUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Responsible for storing and loading OAuth20 scopes.
 *
 * @author Rossitsa Borissova
 */
public class ScopeService {

    static Logger log = LoggerFactory.getLogger(ScopeService.class);

    private static final String MANDATORY_FIELDS_ERROR = "{\"error\":\"scope, description, cc_expires_in and pass_expires_in are mandatory\"}";
    private static final String SCOPE_STORED_OK_MESSAGE = "{\"status\":\"scope successfully stored\"}";
    private static final String SCOPE_STORED_NOK_MESSAGE = "{\"status\":\"scope not stored\"}";
    private static final String SPACE = " ";

    public HttpResponse registerScope(HttpRequest req) {
        String content = req.getContent().toString(CharsetUtil.UTF_8);
        String contentType = req.headers().get(HttpHeaders.Names.CONTENT_TYPE);
        String responseMsg = "";
        // check Content-Type
        if (contentType != null && contentType.contains(Response.APPLICATION_JSON)) {
            ObjectMapper mapper = new ObjectMapper();
            try {
                Scope scope = mapper.readValue(content, Scope.class);
                if (scope.validate()) {
                    // store in the DB, if already exists such a scope, overwrites it
                    boolean ok = DBManagerFactory.getInstance().storeScope(scope);
                    if (ok) {
                        responseMsg = SCOPE_STORED_OK_MESSAGE;
                    } else {
                        responseMsg = SCOPE_STORED_NOK_MESSAGE;
                    }
                } else {
                    log.error("scope is not valid");
                    return Response.createBadRequestResponse(MANDATORY_FIELDS_ERROR);
                }
            } catch (JsonParseException e) {
                log.error("cannot parse scope request", e);
                return Response.createBadRequestResponse(null);
            } catch (JsonMappingException e) {
                log.error("cannot map scope request", e);
                return Response.createBadRequestResponse(null);
            } catch (IOException e) {
                log.error("cannot handle scope request", e);
                return Response.createBadRequestResponse(null);
            }
        } else {
            return Response.createBadRequestResponse(Response.UNSUPPORTED_MEDIA_TYPE);
        }
        return Response.createOkResponse(responseMsg);
    }

    /**
     * Returns either all scopes or scopes for a specific client_id passed as query parameter.
     *
     * @param req request
     * @return If query param client_id is passed, then the scopes for that client_id will be returned.
     * Otherwise, all available scopes will be returned as a response.
     */
    public HttpResponse getScopes(HttpRequest req) {
        QueryStringDecoder dec = new QueryStringDecoder(req.getUri());
        Map<String, List<String>> queryParams = dec.getParameters();
        if(queryParams.containsKey("client_id")) {
            return getScopes(queryParams.get("client_id").get(0));
        }
        List<Scope> scopes = DBManagerFactory.getInstance().getAllScopes();
        ObjectMapper mapper = new ObjectMapper();
        String jsonString;
        try {
            jsonString = mapper.writeValueAsString(scopes);
        } catch (JsonGenerationException e) {
            log.error("cannot load scopes", e);
            return Response.createBadRequestResponse();
        } catch (JsonMappingException e) {
            log.error("cannot load scopes", e);
            return Response.createBadRequestResponse();
        } catch (IOException e) {
            log.error("cannot load scopes", e);
            return Response.createBadRequestResponse();
        }
        return Response.createOkResponse(jsonString);
    }

    public String getValidScope(String scope, String clientId) {
        String validScope = null;
        ClientCredentials creds = DBManagerFactory.getInstance().findClientCredentials(clientId);
        if(creds != null) {
            if(scope == null || scope.length() == 0) {
                // get client scope
                validScope = creds.getScope();
            } else {
                // check that scope exists and is allowed for that client app
                boolean scopeOk = scopeAllowed(scope, creds.getScope());
                if(scopeOk) {
                    validScope = scope;
                }
            }
        }
        return validScope;
    }

    public boolean scopeAllowed(String scope, String allowedScopes) {
        String [] allScopes = allowedScopes.split(SPACE);
        List<String> allowedList = Arrays.asList(allScopes);
        String [] scopes = scope.split(SPACE);
        int allowedCount = 0;
        for(String s : scopes) {
            if (allowedList.contains(s)) {
                allowedCount++;
            }
        }
        return (allowedCount == scopes.length);
    }

    /**
     * Returns value for expires_in by given scope and token type.
     *
     * @param scope scope/s for which expires in will be returned
     * @param tokenGrantType client_credentials or password type
     * @return minimum value of given scope/s expires_in
     */
    public int getExpiresIn(String tokenGrantType, String scope) {
        int expiresIn = Integer.MAX_VALUE;
        List<Scope> scopes = loadScopes(scope);
        boolean ccGrantType = TokenRequest.CLIENT_CREDENTIALS.equals(tokenGrantType);
        if (ccGrantType) {
            for (Scope s : scopes) {
                if (s.getCcExpiresIn() < expiresIn) {
                    expiresIn = s.getCcExpiresIn();
                }
            }
        } else {
            for (Scope s : scopes) {
                if (s.getPassExpiresIn() < expiresIn) {
                    expiresIn = s.getPassExpiresIn();
                }
            }
        }
        if (scopes.size() == 0 || expiresIn == Integer.MAX_VALUE) {
            expiresIn = (ccGrantType) ? OAuthServer.DEFAULT_CC_EXPIRES_IN : OAuthServer.DEFAULT_PASSWORD_EXPIRES_IN;
        }
        return expiresIn;
    }

    protected List<Scope> loadScopes(String scope) {
        String [] scopes = scope.split(SPACE);
        List<Scope> loadedScopes = new ArrayList<Scope>();
        DBManager db = DBManagerFactory.getInstance();
        for (String name : scopes) {
            loadedScopes.add(db.findScope(name));
        }
        return loadedScopes;
    }

    protected HttpResponse getScopes(String clientId) {
        ClientCredentials credentials = DBManagerFactory.getInstance().findClientCredentials(clientId);
        String jsonString;
        if(credentials != null) {
            //scopes are separated by comma
            String scopes = credentials.getScope();
            String [] s = scopes.split(SPACE);
            List<Scope> result = new ArrayList<Scope>();
            for(String name : s) {
                Scope scope = DBManagerFactory.getInstance().findScope(name);
                result.add(scope);
            }

            ObjectMapper mapper = new ObjectMapper();
            try {
                jsonString = mapper.writeValueAsString(result);
            } catch (JsonGenerationException e) {
                log.error("cannot load scopes per clientId", e);
                return Response.createBadRequestResponse();
            } catch (JsonMappingException e) {
                log.error("cannot load scopes per clientId", e);
                return Response.createBadRequestResponse();
            } catch (IOException e) {
                log.error("cannot load scopes per clientId", e);
                return Response.createBadRequestResponse();
            }
        } else {
            return Response.createNotFoundResponse();
        }
        return Response.createOkResponse(jsonString);
    }
}
