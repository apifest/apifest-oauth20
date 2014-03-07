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
import java.util.List;
import java.util.Map;

import org.bson.BSONObject;
import org.bson.types.ObjectId;
import org.codehaus.jackson.map.ObjectMapper;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;
import com.mongodb.DBObject;
import com.mongodb.MongoClient;

/**
 * Connects to the database and responsible for CRUD operations.
 *
 * @author Rossitsa Borissova
 */
public class MongoDBManager implements DBManager{

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

    public MongoDBManager() {
        db = MongoUtil.getMongoClient().getDB("apifest");
    }

    /**
     * Stores client credentials in the DB.
     * @param clientCreds
     */
    public void storeClientCredentials(ClientCredentials clientCreds) {
        try {
            storeObject(clientCreds, CLIENTS_COLLECTION_NAME);
        } catch (IOException e) {
            log.error("Object not stored in DB", e);
        }
    }

    /**
     * Loads a client credentials from DB by passed clientId.
     * @param clientId client id
     * @return client credential object that will be stored in the DB
     */
    @SuppressWarnings("unchecked")
    @Override
    public ClientCredentials findClientCredentials(String clientId) {
        BSONObject result = (BSONObject) findObjectById(clientId, ID_NAME, CLIENTS_COLLECTION_NAME);
        if(result != null){
            Map<String, Object> mapLoaded = result.toMap();
            ClientCredentials loadedCreds = ClientCredentials.loadFromMap(mapLoaded);
            log.debug(loadedCreds.getName());
            return loadedCreds;
        } else {
            return null;
        }
    }

    /**
     * Stores auth codes in the DB.
     * @param authCode that will be stored in the DB
     */
    public void storeAuthCode(AuthCode authCode) {
        try {
            storeObject(authCode, AUTH_CODE_COLLECTION_NAME);
        } catch (IOException e) {
            log.error("Object not stored in DB", e);
        }
    }

    /**
     * Loads an auth code record from DB by passed authCode with status valid=true.
     * @param authCode authCode
     * @return auth code object
     */
    @SuppressWarnings("unchecked")
    @Override
    public AuthCode findAuthCode(String authCode, String redirectUri) {
        BasicDBObject keys = new BasicDBObject();
        keys.put(AUTH_CODE_ID_NAME, authCode);
        keys.put(REDIRECT_URI_NAME, redirectUri);
        keys.put(VALID_NAME, true);
        DBCursor list = db.getCollection(AUTH_CODE_COLLECTION_NAME).find(new BasicDBObject(keys));
        while(list.hasNext()) {
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

    /**
     * Stores access tokens in the DB.
     * @param authCode that will be stored in the DB
     */
    public void storeAccessToken(AccessToken accessToken) {
        try {
            storeObject(accessToken, ACCESS_TOKEN_COLLECTION_NAME);
        } catch (IOException e) {
            log.error("Object not stored in DB", e);
        }
    }

    /**
     * Loads an access token record from DB by passed accessToken
     * @param accessToken access token
     * @return access token object
     */
    @SuppressWarnings("unchecked")
    // TODO: Check clientId is OK
    @Override
    public AccessToken findAccessToken(String accessToken) {
        BasicDBObject dbObject = new BasicDBObject();
        dbObject.put(ACCESS_TOKEN_ID_NAME, accessToken);
        //dbObject.put(CLIENTS_ID_NAME, clientId);
        dbObject.put(VALID_NAME, true);
        DBCollection coll = db.getCollection(ACCESS_TOKEN_COLLECTION_NAME);
        List<DBObject> list = coll.find(dbObject).toArray();
        if(list.size() > 1) {
            //throw exception
            log.warn("Several access tokens found");
            return null;
        }
        if(list.size() > 0) {
            Map<String, Object> mapLoaded = list.get(0).toMap();
            return AccessToken.loadFromMap(mapLoaded);
        } else {
            log.debug("No access token found");
            return null;
        }
    }

    /**
     * Loads an access token record from DB by passed refreshToken
     * @param refreshToken refresh token
     * @param clientId client id
     * @return access token object
     */
    @SuppressWarnings("unchecked")
    @Override
    public AccessToken findAccessTokenByRefreshToken(String refreshToken, String clientId) {
        BasicDBObject dbObject = new BasicDBObject();
        dbObject.put(REFRESH_TOKEN_ID_NAME, refreshToken);
        dbObject.put(CLIENTS_ID_NAME, clientId);
        dbObject.put(VALID_NAME, true);
        DBCollection coll = db.getCollection(ACCESS_TOKEN_COLLECTION_NAME);
        List<DBObject> list = coll.find(dbObject).toArray();
        if(list != null && list.size() == 1){
            Map<String, Object> mapLoaded = list.get(0).toMap();
            AccessToken loadedAccessToken = AccessToken.loadFromMap(mapLoaded);
            log.debug(loadedAccessToken.getToken());
            return loadedAccessToken;
        } else {
            return null;
        }
    }

    @Override
    public void updateAccessTokenValidStatus(String accessToken, boolean valid) {
          BasicDBObject dbObject = new BasicDBObject();
          dbObject.put("token", accessToken);
          DBCollection coll = db.getCollection(ACCESS_TOKEN_COLLECTION_NAME);
          List<DBObject> list = coll.find(dbObject).toArray();
          if(list.size() > 0) {
              DBObject newObject = list.get(0);
              newObject.put("valid", valid);
              coll.findAndModify(dbObject, newObject);
          }
    }

    public void updateAuthCodeValidStatus(String authCode, boolean valid) {
        BasicDBObject dbObject = new BasicDBObject();
        dbObject.put("code", authCode);
        DBCollection coll = db.getCollection(AUTH_CODE_COLLECTION_NAME);
        List<DBObject> list = coll.find(dbObject).toArray();
        if(list.size() > 0) {
            DBObject newObject = list.get(0);
            newObject.put("valid", valid);
            coll.findAndModify(dbObject, newObject);
        }
    }

    /**
     * Validates passed clientId and clientSecret.
     * @param clientId client id of the client
     * @param clientSecret client secret of the client
     * @return true when such a client exists, otherwise false
     */
    @Override
    public boolean validClient(String clientId, String clientSecret) {
        DBCollection coll = db.getCollection(CLIENTS_COLLECTION_NAME);
        BasicDBObject query = new BasicDBObject(ID_NAME, clientId);
        BSONObject result = (BSONObject) getObject(coll, query);
        if(result != null){
            return result.get("secret").equals(clientSecret);
        }
        return false;
    }

    protected Object findObjectByObjectId(String id, String collectionName) {
        DBCollection coll = db.getCollection(collectionName);
        ObjectId objId = new ObjectId(id);
        BasicDBObject query = new BasicDBObject(ID_NAME, objId);
        return getObject(coll, query);
    }

    @SuppressWarnings("unchecked")
    protected void storeObject(Object object, String collectionName) throws IOException {
        JSONObject json = new JSONObject(object);
        if(!json.isNull("id")) {
            constructDbId(json);
        } else {
            json.remove("id");
        }
        Map<String, Object> result = new ObjectMapper().readValue(json.toString(), Map.class);
        BasicDBObject dbObject = new BasicDBObject(result);

        DBCollection coll = db.getCollection(collectionName);
        coll.insert(dbObject);
        log.debug("dbObject:", result);
    }

    protected void constructDbId(JSONObject json) {
        try {
            String id = json.getString("id");
            json.remove("id");
            json.put(ID_NAME, id);
        } catch (JSONException e) {
            log.error("No id set to JSON object {} ", json);
        }
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
            if(cursor != null) {
                cursor.close();
            }
        }
        return result;
    }

}
