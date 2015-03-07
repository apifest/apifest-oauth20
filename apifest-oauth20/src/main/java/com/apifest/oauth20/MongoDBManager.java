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
import java.util.List;
import java.util.Map;

import org.bson.BSONObject;
import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;
import com.mongodb.DBObject;
import com.mongodb.MongoClient;
import com.mongodb.WriteResult;

/**
 * Connects to the database and responsible for CRUD operations.
 *
 * @author Rossitsa Borissova
 */
public class MongoDBManager implements DBManager {

    protected static MongoClient mongoClient;
    protected static DB db;

    protected static Logger log = LoggerFactory.getLogger(DBManager.class);

    protected static final String CLIENTS_COLLECTION_NAME = "clients";
    protected static final String ID_NAME = "_id";
    protected static final String CLIENTS_ID_NAME = "clientId";

    protected static final String AUTH_CODE_COLLECTION_NAME = "authCodes";
    protected static final String AUTH_CODE_ID_NAME = "code";

    protected static final String ACCESS_TOKEN_COLLECTION_NAME = "accessTokens";
    protected static final String ACCESS_TOKEN_ID_NAME = "token";

    protected static final String REFRESH_TOKEN_ID_NAME = "refreshToken";
    protected static final String VALID_NAME = "valid";
    protected static final String REDIRECT_URI_NAME = "redirectUri";

    protected static final String SCOPE_COLLECTION_NAME = "scopes";
    protected static final String SCOPE_ID_NAME = "name";

    protected static final String USER_ID = "userId";

    public MongoDBManager() {
        db = MongoUtil.getDB();
    }

    /*
     * @see com.apifest.oauth20.DBManager#storeClientCredentials(com.apifest.oauth20.ClientCredentials)
     */
    // REVISIT: change interface to throw IOException
    @Override
    public void storeClientCredentials(ClientCredentials clientCreds) {
        try {
            storeObject(clientCreds, CLIENTS_COLLECTION_NAME);
        } catch (IOException e) {
            log.error("Object not stored in DB", e);
        }
    }

    /*
     * @see com.apifest.oauth20.DBManager#findClientCredentials(java.lang.String)
     */
    @SuppressWarnings("unchecked")
    @Override
    public ClientCredentials findClientCredentials(String clientId) {
        BSONObject result = (BSONObject) findObjectById(clientId, ID_NAME, CLIENTS_COLLECTION_NAME);
        if (result != null) {
            Map<String, Object> mapLoaded = result.toMap();
            ClientCredentials loadedCreds = ClientCredentials.loadFromMap(mapLoaded);
            log.debug(loadedCreds.getName());
            return loadedCreds;
        } else {
            return null;
        }
    }

    /*
     * @see com.apifest.oauth20.DBManager#storeAuthCode(com.apifest.oauth20.AuthCode)
     */
    @Override
    public void storeAuthCode(AuthCode authCode) {
        try {
            storeObject(authCode, AUTH_CODE_COLLECTION_NAME);
        } catch (IOException e) {
            log.error("Object not stored in DB", e);
        }
    }

    /*
     * @see com.apifest.oauth20.DBManager#findAuthCode(java.lang.String, java.lang.String)
     */
    @SuppressWarnings("unchecked")
    @Override
    public AuthCode findAuthCode(String authCode, String redirectUri) {
        BasicDBObject keys = new BasicDBObject();
        keys.put(AUTH_CODE_ID_NAME, authCode);
        keys.put(REDIRECT_URI_NAME, redirectUri);
        keys.put(VALID_NAME, true);
        DBCursor list = db.getCollection(AUTH_CODE_COLLECTION_NAME).find(new BasicDBObject(keys));
        while (list.hasNext()) {
            DBObject result = list.next();
            Map<String, Object> mapLoaded = result.toMap();
            AuthCode loadedAuthCode = AuthCode.loadFromMap(mapLoaded);
            log.debug(loadedAuthCode.getClientId());
            list.close();
            return loadedAuthCode;
        }
        list.close();
        return null;
    }

    /*
     * @see com.apifest.oauth20.DBManager#storeAccessToken(com.apifest.oauth20.AccessToken)
     */
    @Override
    public void storeAccessToken(AccessToken accessToken) {
        try {
            storeObject(accessToken, ACCESS_TOKEN_COLLECTION_NAME);
        } catch (IOException e) {
            log.error("Object not stored in DB", e);
        }
    }

    /*
     * @see com.apifest.oauth20.DBManager#findAccessToken(java.lang.String)
     */
    @SuppressWarnings("unchecked")
    @Override
    public AccessToken findAccessToken(String accessToken) {
        BasicDBObject dbObject = new BasicDBObject();
        dbObject.put(ACCESS_TOKEN_ID_NAME, accessToken);
        dbObject.put(VALID_NAME, true);
        DBCollection coll = db.getCollection(ACCESS_TOKEN_COLLECTION_NAME);
        List<DBObject> list = coll.find(dbObject).toArray();
        if (list.size() > 1) {
            // throw exception
            log.warn("Several access tokens found");
            return null;
        }
        if (list.size() > 0) {
            Map<String, Object> mapLoaded = list.get(0).toMap();
            // convert details map to String
            if (mapLoaded.get("details") instanceof BasicDBObject) {
                BasicDBObject details = (BasicDBObject) mapLoaded.get("details");
                mapLoaded.put("details", details.toString());
            }
            return AccessToken.loadFromMap(mapLoaded);
        } else {
            log.debug("No access token found");
            return null;
        }
    }

    /*
     * @see com.apifest.oauth20.DBManager#findAccessTokenByRefreshToken(java.lang.String, java.lang.String)
     */
    @SuppressWarnings("unchecked")
    @Override
    public AccessToken findAccessTokenByRefreshToken(String refreshToken, String clientId) {
        BasicDBObject dbObject = new BasicDBObject();
        // TODO: add indexes
        dbObject.put(REFRESH_TOKEN_ID_NAME, refreshToken);
        dbObject.put(CLIENTS_ID_NAME, clientId);
        DBCollection coll = db.getCollection(ACCESS_TOKEN_COLLECTION_NAME);
        List<DBObject> list = coll.find(dbObject).toArray();
        if (list != null && list.size() == 1) {
            Map<String, Object> mapLoaded = list.get(0).toMap();
            // convert details list to String
            if (mapLoaded.get("details") instanceof BasicDBObject) {
                BasicDBObject details = (BasicDBObject) mapLoaded.get("details");
                mapLoaded.put("details", details.toString());
            }
            AccessToken loadedAccessToken = AccessToken.loadFromMap(mapLoaded);
            log.debug(loadedAccessToken.getToken());
            return loadedAccessToken;
        } else {
            return null;
        }
    }

    /*
     * @see com.apifest.oauth20.DBManager#updateAccessTokenValidStatus(java.lang.String, boolean)
     */
    @Override
    public void updateAccessTokenValidStatus(String accessToken, boolean valid) {
        BasicDBObject dbObject = new BasicDBObject();
        dbObject.put("token", accessToken);
        DBCollection coll = db.getCollection(ACCESS_TOKEN_COLLECTION_NAME);
        List<DBObject> list = coll.find(dbObject).toArray();
        if (list.size() > 0) {
            DBObject newObject = list.get(0);
            newObject.put("valid", valid);
            coll.findAndModify(dbObject, newObject);
        }
    }

    /*
     * @see com.apifest.oauth20.DBManager#updateAuthCodeValidStatus(java.lang.String, boolean)
     */
    @Override
    public void updateAuthCodeValidStatus(String authCode, boolean valid) {
        BasicDBObject dbObject = new BasicDBObject();
        dbObject.put("code", authCode);
        DBCollection coll = db.getCollection(AUTH_CODE_COLLECTION_NAME);
        List<DBObject> list = coll.find(dbObject).toArray();
        if (list.size() > 0) {
            DBObject newObject = list.get(0);
            newObject.put("valid", valid);
            coll.findAndModify(dbObject, newObject);
        }
    }

    /*
     * @see com.apifest.oauth20.DBManager#validClient(java.lang.String, java.lang.String)
     */
    @Override
    public boolean validClient(String clientId, String clientSecret) {
        DBCollection coll = db.getCollection(CLIENTS_COLLECTION_NAME);
        BasicDBObject query = new BasicDBObject(ID_NAME, clientId);
        BSONObject result = (BSONObject) getObject(coll, query);
        if (result != null) {
            return (result.get("secret").equals(clientSecret) && String.valueOf(ClientCredentials.ACTIVE_STATUS).equals(result.get("status")));
        }
        return false;
    }

    /*
     * @see com.apifest.oauth20.DBManager#storeScope(com.apifest.oauth20.Scope)
     */
    @Override
    @SuppressWarnings("unchecked")
    public boolean storeScope(Scope scope) {
        boolean stored = false;
        String id = scope.getScope();
        Gson gson = new Gson();
        String json = gson.toJson(scope);
        JsonParser parser = new JsonParser();
        JsonObject jsonObj= parser.parse(json).getAsJsonObject();
        jsonObj.remove("scope");
        // use scope name as _id
        jsonObj.addProperty(ID_NAME, id);

        try {
            // use ObjectMapper in order to represent expiresIn as integer not as double - 100 instead of 100.00
            Map<String, Object> result = new ObjectMapper().readValue(jsonObj.toString(), Map.class);

            // if scope already exits, updates it, otherwise creates the scope
            BasicDBObject query = new BasicDBObject(ID_NAME, id);
            BasicDBObject newObject = new BasicDBObject(result);
            DBCollection coll = db.getCollection(SCOPE_COLLECTION_NAME);
            coll.update(query, newObject, true, false);
            stored = true;
        } catch (JsonParseException e) {
            log.error("cannot store scope {}", scope.getScope(), e);
        } catch (JsonMappingException e) {
            log.error("cannot store scope {}", scope.getScope(), e);
        } catch (IOException e) {
            log.error("cannot store scope {}", scope.getScope(), e);
        }

        return stored;
    }

    /*
     * @see com.apifest.oauth20.DBManager#getAllScopes()
     */
    @Override
    @SuppressWarnings("unchecked")
    public List<Scope> getAllScopes() {
        List<Scope> list = new ArrayList<Scope>();
        DBCollection coll = db.getCollection(SCOPE_COLLECTION_NAME);
        List<DBObject> result = coll.find().toArray();
        for (DBObject obj : result) {
            Map<String, Object> mapLoaded = obj.toMap();
            Scope scope = Scope.loadFromMap(mapLoaded);
            list.add(scope);
        }
        return list;
    }

    /*
     * @see com.apifest.oauth20.DBManager#findScope(java.lang.String)
     */
    @Override
    @SuppressWarnings("unchecked")
    public Scope findScope(String scopeName) {
        BSONObject result = (BSONObject) findObjectById(scopeName, ID_NAME, SCOPE_COLLECTION_NAME);
        if (result != null) {
            return Scope.loadFromMap(result.toMap());
        } else {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    protected void storeObject(Object object, String collectionName) throws IOException {
        String json = constructDbId(object);
        // use ObjectMapper in order to represent expiresIn as integer not as double - 100 instead of 100.00
        Map<String, Object> result = new ObjectMapper().readValue(json, Map.class);
        BasicDBObject dbObject = new BasicDBObject(result);

        DBCollection coll = db.getCollection(collectionName);
        coll.insert(dbObject);
        log.debug("dbObject:", result);
    }

    // replaces id with _id, if id presents in the object
    protected String constructDbId(Object object) {
        Gson gson = new Gson();
        String json = gson.toJson(object);
        JsonParser parser = new JsonParser();
        JsonObject jsonObj= parser.parse(json).getAsJsonObject();
        if(jsonObj.has("id")) {
            String id = jsonObj.get("id").getAsString();
            jsonObj.remove("id");
            jsonObj.addProperty(ID_NAME, id);
        }
        return jsonObj.toString();
    }

    protected Object findObjectById(String id, String idName, String collectionName) {
        DBCollection coll = db.getCollection(collectionName);
        BasicDBObject query = new BasicDBObject(idName, id);
        return getObject(coll, query);
    }

    protected Object getObject(DBCollection coll, BasicDBObject query) {
        DBCursor cursor = coll.find(query);
        Object result = null;
        try {
            // TODO: if more than once throw exception
            while (cursor.hasNext()) {
                result = cursor.next();
                log.debug("found: " + result);
            }
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
        return result;
    }

    /*
     * @see com.apifest.oauth20.DBManager#updateClientAppScope(java.lang.String)
     */
    @Override
    public boolean updateClientApp(String clientId, String scope, String description, Integer status, Map<String, String> applicationDetails) {
        boolean updated = false;
        DBCollection coll = db.getCollection(CLIENTS_COLLECTION_NAME);
        BasicDBObject query = new BasicDBObject(ID_NAME, clientId);
        List<DBObject> list = coll.find(query).toArray();
        if (list.size() > 0) {
            DBObject newObject = list.get(0);
            if (scope != null && scope.length() > 0) {
                newObject.put("scope", scope);
            }
            if (description != null && description.length() > 0) {
                newObject.put("descr", description);
            }
            if (status != null) {
                newObject.put("status", status);
            }
            if (applicationDetails != null && applicationDetails.size() > 0) {
                newObject.put("applicationDetails", applicationDetails);
            }
            coll.findAndModify(query, newObject);
            updated = true;
        }
        return updated;
    }

    /*
     * @see com.apifest.oauth20.DBManager#getAllApplications()
     */
    @Override
    @SuppressWarnings("unchecked")
    public List<ApplicationInfo> getAllApplications() {
        List<ApplicationInfo> list = new ArrayList<ApplicationInfo>();
        DBCollection coll = db.getCollection(CLIENTS_COLLECTION_NAME);
        List<DBObject> result = coll.find().toArray();
        for (DBObject obj : result) {
            BSONObject bson = obj;
            Map<String, Object> mapLoaded = bson.toMap();
            ApplicationInfo loadedCreds = ApplicationInfo.loadFromMap(mapLoaded);
            list.add(loadedCreds);
        }
        return list;
    }

    /*
     * @see com.apifest.oauth20.DBManager#deleteScope(java.lang.String)
     */
    @Override
    public boolean deleteScope(String scopeName) {
        DBCollection coll = db.getCollection(SCOPE_COLLECTION_NAME);
        BasicDBObject query = new BasicDBObject(ID_NAME, scopeName);
        WriteResult result = coll.remove(query);
        return (result.getN() == 1) ? true : false;
    }

    /*
     * @see com.apifest.oauth20.DBManager#getAccessTokenByUserIdAndClientApp(java.lang.String, java.lang.String)
     */
    @Override
    @SuppressWarnings("unchecked")
    public List<AccessToken> getAccessTokenByUserIdAndClientApp(String userId, String clientId) {
        List<AccessToken> accessTokens = new ArrayList<AccessToken>();
        BasicDBObject dbObject = new BasicDBObject();
        // TODO: add indexes
        dbObject.put(USER_ID, userId);
        dbObject.put(CLIENTS_ID_NAME, clientId);
        dbObject.put(VALID_NAME, true);
        DBCollection coll = db.getCollection(ACCESS_TOKEN_COLLECTION_NAME);
        List<DBObject> list = coll.find(dbObject).toArray();
        for (DBObject object : list) {
            Map<String, Object> mapLoaded = object.toMap();
            // convert details list to String
            if (mapLoaded.get("details") instanceof BasicDBObject) {
                BasicDBObject details = (BasicDBObject) mapLoaded.get("details");
                mapLoaded.put("details", details.toString());
            }
            AccessToken loadedAccessToken = AccessToken.loadFromMap(mapLoaded);
            accessTokens.add(loadedAccessToken);
        }
        return accessTokens;
    }

    @Override
    public void removeAccessToken(String accessToken) {
        BasicDBObject dbObject = new BasicDBObject();
        dbObject.put(ACCESS_TOKEN_ID_NAME, accessToken);
        DBCollection coll = db.getCollection(ACCESS_TOKEN_COLLECTION_NAME);
        List<DBObject> list = coll.find(dbObject).toArray();
        if (list.size() > 0) {
            DBObject newObject = list.get(0);
            coll.findAndModify(dbObject, newObject);
            coll.remove(dbObject);
        }
    }

}
