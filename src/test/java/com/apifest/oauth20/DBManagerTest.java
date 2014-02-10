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

import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;
import static org.mockito.BDDMockito.*;
import static org.testng.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.bson.BSONObject;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;
import com.mongodb.DBObject;

/**
 * @author Rossitsa Borissova
 */
public class DBManagerTest {

    DBManager dbManager;
    DB db;
    DBCollection coll;

    @BeforeMethod
    public void setup() {
        dbManager = spy(new DBManager());
        DBManager.log = mock(Logger.class);
        db = mock(DB.class);
        coll = mock(DBCollection.class);
        dbManager.db = db;
    }

    @Test
    public void when_insert_client_credentials_invoke_insert_object() throws Exception {
        // GIVEN
        ClientCredentials cred = new ClientCredentials("Test");
        willDoNothing().given(dbManager).storeObject(cred, DBManager.CLIENTS_COLLECTION_NAME);

        // WHEN
        dbManager.storeClientCredentials(cred);

        // THEN
        verify(dbManager).storeObject(cred, DBManager.CLIENTS_COLLECTION_NAME);
    }

    @Test
    public void when_insert_client_credentials_invoke_insert_on_collection() throws Exception {
        // GIVEN
        ClientCredentials cred = new ClientCredentials("Test");
        given(db.getCollection(DBManager.CLIENTS_COLLECTION_NAME)).willReturn(coll);

        // WHEN
        dbManager.storeObject(cred, DBManager.CLIENTS_COLLECTION_NAME);

        // THEN
        verify(coll).insert(any(DBObject.class));
    }

    @Test
    public void when_find_client_credentials_by_id_invoke_find_objectby_id() throws Exception {
        // GIVEN
        ClientCredentials cred = new ClientCredentials("Test");
        BSONObject bson = mock(BSONObject.class);
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("name", "Test App");
        map.put("_id", "763273054098803");
        map.put("secret", "2475a03c2da45c5427c25747ab80b2e1");
        map.put("created", 1365191565324l);
        map.put("type", 1);
        map.put("status", 1);
        willReturn(map).given(bson).toMap();
        willReturn(bson).given(dbManager).findObjectById(cred.getId(), DBManager.ID_NAME, DBManager.CLIENTS_COLLECTION_NAME);

        // WHEN
        dbManager.findClientCredentials(cred.getId());

        // THEN
        verify(dbManager).findObjectById(cred.getId(), DBManager.ID_NAME, DBManager.CLIENTS_COLLECTION_NAME);
    }


    @Test
    public void when_find_object_by_id_invoke_find_on_collection() throws Exception {
        ClientCredentials cred = new ClientCredentials("Test");
        DBCursor cursor = mock(DBCursor.class);
        given(coll.find(any(DBObject.class))).willReturn(cursor);
        given(db.getCollection(DBManager.CLIENTS_COLLECTION_NAME)).willReturn(coll);

        // WHEN
        dbManager.findObjectById(cred.getId(), DBManager.CLIENTS_ID_NAME, DBManager.CLIENTS_COLLECTION_NAME);

        // THEN
        verify(coll).find(any(DBObject.class));
    }


    @Test
    public void when_no_object_found_find_by_id_return_null() throws Exception {
     // GIVEN
        ClientCredentials cred = new ClientCredentials("Test");
        willReturn(null).given(dbManager).findObjectById
            (cred.getId(), DBManager.ID_NAME, DBManager.CLIENTS_COLLECTION_NAME);

        // WHEN
        ClientCredentials result = dbManager.findClientCredentials(cred.getId());

        // THEN
        assertNull(result);
    }

    @Test
    public void when_json_contains_id_invoke_constructDbId() throws Exception {
        // GIVEN
        ClientCredentials cred = new ClientCredentials("Test");
        given(db.getCollection(DBManager.CLIENTS_COLLECTION_NAME)).willReturn(coll);

        // WHEN
        dbManager.storeObject(cred, DBManager.CLIENTS_COLLECTION_NAME);

        // THEN
        verify(dbManager).constructDbId(any(JSONObject.class));
    }

    @Test
    public void when_json_contains_NO_id_NOT_invoke_constructDbId() throws Exception {
        // GIVEN
        AuthCode code = new AuthCode(AuthCode.generate(), "763273054098803",
                "http://example.com", "xyz", "basic", "code", "1234");
        given(db.getCollection(DBManager.CLIENTS_COLLECTION_NAME)).willReturn(coll);

        // WHEN
        dbManager.storeObject(code, DBManager.CLIENTS_COLLECTION_NAME);

        // THEN
        verify(dbManager, times(0)).constructDbId(any(JSONObject.class));
    }


    @Test
    public void when_valid_client_check_clientId_and_secret() throws Exception {
        // GIVEN
        String clientId = "clientId";
        String clientSecret = "clientSecret";
        given(db.getCollection(DBManager.CLIENTS_COLLECTION_NAME)).willReturn(coll);
        BSONObject bson = mock(BSONObject.class);
        given(bson.get("secret")).willReturn(clientSecret);
        willReturn(bson).given(dbManager).getObject(any(DBCollection.class), any(BasicDBObject.class));

        // WHEN
        boolean result = dbManager.validClient(clientId, clientSecret);

        // THEN
        assertTrue(result);
    }

    @Test
    public void when_invalid_secret_return_false() throws Exception {
        // GIVEN
        String clientId = "clientId";
        String clientSecret = "clientSecret";
        given(db.getCollection(DBManager.CLIENTS_COLLECTION_NAME)).willReturn(coll);
        BSONObject bson = mock(BSONObject.class);
        given(bson.get("secret")).willReturn("somthing_else");
        willReturn(bson).given(dbManager).getObject(any(DBCollection.class), any(BasicDBObject.class));

        // WHEN
        boolean result = dbManager.validClient(clientId, clientSecret);

        // THEN
        assertFalse(result);
    }

}
