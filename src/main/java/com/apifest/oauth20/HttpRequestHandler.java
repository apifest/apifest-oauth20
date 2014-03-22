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
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;

import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.handler.codec.http.DefaultHttpResponse;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpMethod;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.HttpVersion;
import org.jboss.netty.handler.codec.http.QueryStringDecoder;
import org.jboss.netty.util.CharsetUtil;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.apifest.oauth20.AuthorizationServer;
import com.apifest.oauth20.ClientCredentials;

/**
 * Handler for requests received on the server.
 *
 * @author Rossitsa Borissova
 */
public class HttpRequestHandler extends SimpleChannelUpstreamHandler {

//    public static final String NOT_FOUND_CONTENT = "{\"error\":\"Not found\"}";
    protected static final String OAUTH_REGISTER_CLIENT_URI = "/oauth20/register";
    protected static final String AUTH_CODE_GENERATE_URI = "/oauth20/authorize";
    protected static final String ACCESS_TOKEN_GENERATE_URI = "/oauth20/token";
    protected static final String ACCESS_TOKEN_VALIDATE_URI = "/oauth20/token/validate";
    protected static final String APPLICATION_INFO_URI = "/oauth20/application";
    protected static final String ACCESS_TOKEN_REVOKE_URI = "/oauth20/token/revoke";

    protected static final String OAUTH_CLIENT_SCOPE_URI = "/oauth20/scopes";

//    private static final String APPLICATION_JSON = "application/json";

    protected Logger log = LoggerFactory.getLogger(HttpRequestHandler.class);

    protected static Logger accessTokensLog = LoggerFactory.getLogger("accessTokens");

    protected AuthorizationServer auth = new AuthorizationServer();

    @Override
    public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) {
        final Channel channel = ctx.getChannel();
        Object message = e.getMessage();
        if(message instanceof HttpRequest) {
            HttpRequest req = (HttpRequest) message;
            String content = new String(req.getContent().array());
            log.debug("content: {}" , content);

            HttpMethod method = req.getMethod();
            String rawUri = req.getUri();
            try {
                URI u = new URI(rawUri);
                rawUri = u.getRawPath();
            } catch (URISyntaxException e2) {
                log.error("URI syntax exception {}", rawUri);
            }

            HttpResponse response = null;
            if(OAUTH_REGISTER_CLIENT_URI.equals(rawUri) && method.equals(HttpMethod.GET)) {
                response = handleRegister(req);
            } else if(AUTH_CODE_GENERATE_URI.equals(rawUri) && method.equals(HttpMethod.GET)) {
                response = handleAuthorize(req);
            } else if(ACCESS_TOKEN_GENERATE_URI.equals(rawUri) && method.equals(HttpMethod.POST)) {
                response = handleToken(req);
            } else if(ACCESS_TOKEN_VALIDATE_URI.equals(rawUri) && method.equals(HttpMethod.GET)) {
                response = handleTokenValidate(req);
            } else if(APPLICATION_INFO_URI.equals(rawUri) && method.equals(HttpMethod.GET)){
                response = handleApplicationInfo(req);
            } else if(ACCESS_TOKEN_REVOKE_URI.equals(rawUri) && method.equals(HttpMethod.POST)){
                response = handleTokenRevoke(req);
            } else if(OAUTH_CLIENT_SCOPE_URI.equals(rawUri) && method.equals(HttpMethod.POST)){
                response = handleRegisterScope(req);
            } else if(OAUTH_CLIENT_SCOPE_URI.equals(rawUri) && method.equals(HttpMethod.GET)){
                response = handleGetScopes(req);
            }else {
                response = Response.createNotFoundResponse();
            }
            ChannelFuture future = channel.write(response);
            future.addListener(ChannelFutureListener.CLOSE);
            return;

        } else {
            log.info("write response here from the BE");
        }
    }

    private HttpResponse handleApplicationInfo(HttpRequest req) {
        HttpResponse response = null;
        QueryStringDecoder dec = new QueryStringDecoder(req.getUri());
        Map<String, List<String>> params = dec.getParameters();
        String clientId = QueryParameter.getFirstElement(params, "client_id");
        boolean valid = auth.isValidClientId(clientId);
        log.debug("client_id valid:" + valid);
        if(valid) {
            String appName = auth.getApplicationName(clientId);
            JSONObject json = new JSONObject();
            try {
                json.put("application_name", appName);
            } catch (JSONException e) {
                log.error("Cannot extract application name", e);
            }
            log.debug(json.toString());
            response = Response.createOkResponse(json.toString());
        } else {
            // REVISIT: Think about another HTTP status
            response = Response.createOkResponse(Response.INVALID_CLIENT_ID);
        }
        return response;
    }

    protected HttpResponse handleTokenValidate(HttpRequest req) {
        HttpResponse response = null;
        QueryStringDecoder dec = new QueryStringDecoder(req.getUri());
        Map<String, List<String>> params = dec.getParameters();
        // TODO: Check clientId?
        AccessToken token = auth.isValidToken(QueryParameter.getFirstElement(params, "token"));
        log.debug("token valid:" + token);
        if(token != null) {
            JSONObject json = new JSONObject(token);
            log.debug(json.toString());
            response = Response.createOkResponse(json.toString());
        } else {
            response = Response.createUnauthorizedResponse();
        }
        return response;
    }

    protected HttpResponse handleToken(HttpRequest req) {
        HttpResponse response = null;
        try {
            AccessToken accessToken = auth.issueAccessToken(req);
            if(accessToken != null) {
                ObjectMapper mapper = new ObjectMapper();
                String jsonString = mapper.writeValueAsString(accessToken);
                log.debug("access token:" + jsonString);
                response = Response.createOkResponse(jsonString);
                accessTokensLog.debug("token {}", jsonString);
            }
        } catch(OAuthException ex) {
            response = Response.createOAuthExceptionResponse(ex);
        } catch (JsonGenerationException e1) {
           log.error("error generating JSON, {}", e1);
        } catch (JsonMappingException e1) {
            log.error("error mapping JSON, {}", e1);
        } catch (IOException e1) {
            log.error("IO exception, {}", e1);
        }
        if(response == null) {
            // REVISIT: Think about another HTTP status
            response = Response.createOkResponse(Response.CANNOT_ISSUE_TOKEN);
        }
        return response;
    }

    private HttpResponse handleAuthorize(HttpRequest req) {
        HttpResponse response = null;
        try {
            String redirectURI = auth.issueAuthorizationCode(req);
            // TODO: validation http protocol?
            log.debug("redirectURI: {}", redirectURI);

            // return auth_code
            JSONObject obj = new JSONObject();
            obj.put("redirect_uri", redirectURI);
            response = Response.createOkResponse(obj.toString());
            accessTokensLog.info("authCode {}", obj.toString());
        } catch (OAuthException ex) {
            response = Response.createOAuthExceptionResponse(ex);
        } catch (JSONException e) {
            log.debug("problen JSON parsing", e);
        }
        return response;
    }

    protected HttpResponse handleRegister(HttpRequest req) {
        HttpResponse response = null;
        try {
            ClientCredentials creds = auth.issueClientCredentials(req);
            ObjectMapper mapper = new ObjectMapper();
            String jsonString = mapper.writeValueAsString(creds);
            log.debug("credentials:" + jsonString);
            response = Response.createOkResponse(jsonString);
        } catch(OAuthException ex) {
            response = Response.createOAuthExceptionResponse(ex);
        } catch (JsonGenerationException e1) {
           log.error("error generating JSON, {}", e1);
        } catch (JsonMappingException e1) {
            log.error("error mapping JSON, {}", e1);
        } catch (IOException e1) {
            log.error("IO exception, {}", e1);
        }
        if(response == null) {
            // REVISIT: Think about another HTTP status
            response = Response.createOkResponse(Response.CANNOT_REGISTER_APP);
        }
        return response;
    }

    protected HttpResponse handleTokenRevoke(HttpRequest req) {
        boolean revoked = false;
        try {
            revoked = auth.revokeToken(req);
        } catch (OAuthException e) {
            log.error("cannot revoke token", e);
            //TODO: return not OK response
        }
        String json = "{\"revoked\":\"" + revoked + "\"}";
        return Response.createOkResponse(json);
    }

    protected HttpResponse handleRegisterScope(HttpRequest req) {
        ScopeService scopeService = new ScopeService();
        return scopeService.registerScope(req);
    }

    protected HttpResponse handleGetScopes(HttpRequest req) {
        String content = req.getContent().toString(CharsetUtil.UTF_8);

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

//    protected HttpResponse createBadRequestResponse(String message) {
//        HttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.BAD_REQUEST);
//        response.setHeader(HttpHeaders.Names.CONTENT_TYPE, APPLICATION_JSON);
//        if(message != null) {
//            ChannelBuffer buf = ChannelBuffers.copiedBuffer(message.getBytes());
//            response.setContent(buf);
//        }
//        response.setHeader(HttpHeaders.Names.CACHE_CONTROL, HttpHeaders.Values.NO_STORE);
//        response.setHeader(HttpHeaders.Names.PRAGMA, HttpHeaders.Values.NO_CACHE);
//        return response;
//    }

//    protected HttpResponse createNotFoundResponse() {
//        HttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.NOT_FOUND);
//        response.setHeader(HttpHeaders.Names.CONTENT_TYPE, APPLICATION_JSON);
//        ChannelBuffer buf = ChannelBuffers.copiedBuffer(NOT_FOUND_CONTENT.getBytes());
//        response.setContent(buf);
//        response.setHeader(HttpHeaders.Names.CACHE_CONTROL, HttpHeaders.Values.NO_STORE);
//        response.setHeader(HttpHeaders.Names.PRAGMA, HttpHeaders.Values.NO_CACHE);
//        return response;
//    }
//
//    protected HttpResponse createOkResponse(String jsonString) {
//        HttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
//        ChannelBuffer buf = ChannelBuffers.copiedBuffer(jsonString.getBytes());
//        response.setContent(buf);
//        response.setHeader(HttpHeaders.Names.CONTENT_TYPE, APPLICATION_JSON);
//        response.setHeader(HttpHeaders.Names.CACHE_CONTROL, HttpHeaders.Values.NO_STORE);
//        response.setHeader(HttpHeaders.Names.PRAGMA, HttpHeaders.Values.NO_CACHE);
//        return response;
//    }

//    protected HttpResponse createOAuthExceptionResponse(OAuthException ex) {
//        HttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, ex.getHttpStatus());
//        ChannelBuffer buf = ChannelBuffers.copiedBuffer(ex.getMessage().getBytes());
//        response.setContent(buf);
//        response.setHeader(HttpHeaders.Names.CONTENT_TYPE, APPLICATION_JSON);
//        response.setHeader(HttpHeaders.Names.CACHE_CONTROL, HttpHeaders.Values.NO_STORE);
//        response.setHeader(HttpHeaders.Names.PRAGMA, HttpHeaders.Values.NO_CACHE);
//        return response;
//    }
//
//    protected HttpResponse createUnauthorizedResponse() {
//        HttpResponse response = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.UNAUTHORIZED);
//        ChannelBuffer buf = ChannelBuffers.copiedBuffer(ErrorResponse.INVALID_ACCESS_TOKEN.getBytes());
//        response.setContent(buf);
//        response.setHeader(HttpHeaders.Names.CACHE_CONTROL, HttpHeaders.Values.NO_STORE);
//        response.setHeader(HttpHeaders.Names.PRAGMA, HttpHeaders.Values.NO_CACHE);
//        return response;
//    }
}
