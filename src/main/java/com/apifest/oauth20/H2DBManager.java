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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.h2.jdbcx.JdbcDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Rossitsa Borissova
 */
public class H2DBManager implements DBManager {

    private JdbcDataSource ds;
    protected static Logger log = LoggerFactory.getLogger(H2DBManager.class);

    // TODO: check column length
    private static final String CREATE_SCOPE_TABLE = "create table scopes (id int primary key, name varchar(255))";

    // TODO: add type column
    private static final String CREATE_CLIENT_TABLE_SQL = "create table clients (id varchar(255) primary key," +
        "secret varchar(255), name varchar(255), description varchar(255), uri varchar(1024), scope varchar(255)," +
        "status int, created time)";
    private static final String CLIENTS_TABLE = "clients";

    private static final String INSERT_CLIENT_SQL = "insert into clients(id, secret, name, description, uri, scope, " +
        "status, created) values(?,?,?,?,?,?,?,?)";
    private static final String VALID_CLIENT_SQL = "select id from clients where id=? and secret=?";
    private static final String SELECT_CLIENT_BY_ID_SQL = "select * from clients where id=?";

    private static final String CREATE_ACCESS_TOKEN_TABLE_SQL = "create table access_tokens (token varchar(255) primary key," +
        "refresh_token varchar(255), expires_in int, type varchar(64), scope varchar(255), valid boolean," +
        "client_id varchar(255), user_id varchar(255), created time)";

    private static final String ACCESS_TOKEN_TABLE = "access_tokens";

    private static final String INSERT_ACCESS_TOKEN_SQL = "insert into access_tokens(token, refresh_token, " +
        "expires_in, type, scope, valid, client_id, user_id, created) values(?,?,?,?,?,?,?,?,?)";

    private static final String SELECT_ACCESS_TOKEN_SQL = "select * from access_tokens where token=? and client_id=?";

    public H2DBManager() {
        ds = new JdbcDataSource();
        ds.setURL("jdbc:h2:~/apifest_db");
        ds.setUser("sa");
        ds.setPassword("sa");
    }

    // if table does not exists, create it
    private boolean ensureTableExists(String table, String createStatement) {
        Connection conn = null;
        PreparedStatement st = null;
        ResultSet rs = null;
        boolean exist = false;
        try {
            conn = ds.getConnection();
            st = conn.prepareStatement("select 1 from " + table);
            rs = st.executeQuery();
            if (rs.next()) {
                exist = true;
                log.debug("table already exists");
            }
        } catch (SQLException e) {
            log.error("cannot check tables exist", e);
            executeSQL(createStatement, null);
        } finally {
           closeDBResources(st, rs, conn);
        }
        return exist;
    }

    private void executeSQL(String sql, List<Object> params) {
        Connection conn = null;
        PreparedStatement st = null;
        try {
            conn = ds.getConnection();
            st = conn.prepareStatement(sql);
            int i = 0;
            for(Object obj : params) {
                st.setObject(++i, obj);
            }
            st.execute();
            conn.commit();
        } catch (SQLException e) {
            log.error("cannot execute SQL", e);
        } finally {
            closeDBResources(st, null, conn);
        }
    }

    private boolean recordExists(String sql, List<Object> params) {
        Connection conn = null;
        PreparedStatement st = null;
        ResultSet rs = null;
        boolean valid = false;
        try {
            conn = ds.getConnection();
            st = conn.prepareStatement(sql);
            int i = 0;
            for(Object obj : params) {
                st.setObject(++i, obj);
            }
            rs = st.executeQuery();
            if (rs.next()) {
                valid = true;
            }
        } catch (SQLException e) {
            log.error("cannot execute SQL", e);
        } finally {
            closeDBResources(st, rs, conn);
        }
        return valid;
    }

    /* (non-Javadoc)
     * @see com.apifest.oauth20.DBManager#validClient(java.lang.String, java.lang.String)
     */
    @Override
    public boolean validClient(String clientId, String clientSecret) {
        List<Object> params = new ArrayList<Object>();
        params.add(clientId);
        params.add(clientSecret);
        return recordExists(VALID_CLIENT_SQL, params);
    }

    /* (non-Javadoc)
     * @see com.apifest.oauth20.DBManager#storeClientCredentials(com.apifest.oauth20.ClientCredentials)
     */
    @Override
    @SuppressWarnings("unchecked")
    public void storeClientCredentials(ClientCredentials clientCreds) {
        ensureTableExists(CLIENTS_TABLE, CREATE_CLIENT_TABLE_SQL);
        List<Object> params = new ArrayList<Object>(Arrays.asList(clientCreds.getId(), clientCreds.getSecret(),
                clientCreds.getName(), clientCreds.getDescr(), clientCreds.getUri(), clientCreds.getScope(),
                clientCreds.getStatus(), new Date(clientCreds.getCreated())));
        executeSQL(INSERT_CLIENT_SQL, params);
    }

    /* (non-Javadoc)
     * @see com.apifest.oauth20.DBManager#storeAuthCode(com.apifest.oauth20.AuthCode)
     */
    @Override
    public void storeAuthCode(AuthCode authCode) {
        // TODO Auto-generated method stub

    }

    /* (non-Javadoc)
     * @see com.apifest.oauth20.DBManager#updateAuthCodeValidStatus(java.lang.String, boolean)
     */
    @Override
    public void updateAuthCodeValidStatus(String authCode, boolean valid) {
        // TODO Auto-generated method stub

    }

    /* (non-Javadoc)
     * @see com.apifest.oauth20.DBManager#storeAccessToken(com.apifest.oauth20.AccessToken)
     */
    @Override
    @SuppressWarnings("unchecked")
    public void storeAccessToken(AccessToken accessToken) {
        ensureTableExists(ACCESS_TOKEN_TABLE, CREATE_ACCESS_TOKEN_TABLE_SQL);
        List<Object> params = new ArrayList<Object>(Arrays.asList(accessToken.getToken(), accessToken.getRefreshToken(),
                accessToken.getExpiresIn(), accessToken.getType(), accessToken.getScope(), accessToken.isValid(),
                accessToken.getClientId(), accessToken.getUserId() , new Date(accessToken.getCreated())));
        executeSQL(INSERT_ACCESS_TOKEN_SQL, params);
    }

    /* (non-Javadoc)
     * @see com.apifest.oauth20.DBManager#findAccessTokenByRefreshToken(java.lang.String, java.lang.String)
     */
    @Override
    public AccessToken findAccessTokenByRefreshToken(String refreshToken, String clientId) {
        // TODO Auto-generated method stub
        return null;
    }

    /* (non-Javadoc)
     * @see com.apifest.oauth20.DBManager#updateAccessTokenValidStatus(java.lang.String, boolean)
     */
    @Override
    public void updateAccessTokenValidStatus(String accessToken, boolean valid) {
        // TODO Auto-generated method stub

    }

    /* (non-Javadoc)
     * @see com.apifest.oauth20.DBManager#findAccessToken(java.lang.String)
     */
    @Override
    public AccessToken findAccessToken(String accessToken) {
        // TODO Auto-generated method stub
        //
        return null;
    }

    /* (non-Javadoc)
     * @see com.apifest.oauth20.DBManager#findAuthCode(java.lang.String, java.lang.String)
     */
    @Override
    public AuthCode findAuthCode(String authCode, String redirectUri) {
        // TODO Auto-generated method stub
        return null;
    }

    /* (non-Javadoc)
     * @see com.apifest.oauth20.DBManager#findClientCredentials(java.lang.String)
     */
    @Override
    public ClientCredentials findClientCredentials(String clientId) {
        Connection conn = null;
        PreparedStatement st = null;
        ResultSet rs = null;
        ClientCredentials client = null;
        try {
            conn = ds.getConnection();
            st = conn.prepareStatement(SELECT_CLIENT_BY_ID_SQL);
            st.setString(1, clientId);
            rs = st.executeQuery();
            Map<String, String> map = new HashMap<String, String>();
            if (rs.next()) {
                map.put("_id", rs.getString("id"));
                map.put("secret", rs.getString("secret"));
                map.put("name", rs.getString("name"));
                map.put("uri", rs.getString("uri"));
                map.put("descr", rs.getString("description"));
                // TODO: set default type value
                //map.put("type", rs.getObject(("type"));
                map.put("type", "0");
                map.put("status", rs.getString("status"));
                map.put("created", String.valueOf(rs.getDate("created").getTime()));
                map.put("scope", rs.getString("scope"));
                client = ClientCredentials.loadFromStringMap(map);
            }
        } catch (SQLException e) {
            log.error("cannot execute SQL", e);
        } finally {
            closeDBResources(st, rs, conn);
        }
        return client;
    }

    /* (non-Javadoc)
     * @see com.apifest.oauth20.DBManager#storeScope(com.apifest.oauth20.Scope)
     */
    @Override
    public boolean storeScope(Scope scope) {
        // TODO Auto-generated method stub
        return false;
    }

    /* (non-Javadoc)
     * @see com.apifest.oauth20.DBManager#getAllScopes()
     */
    @Override
    public List<Scope> getAllScopes() {
        // TODO Auto-generated method stub
        return null;
    }

    /* (non-Javadoc)
     * @see com.apifest.oauth20.DBManager#findScope(java.lang.String)
     */
    @Override
    public Scope findScope(String scopeName) {
        // TODO Auto-generated method stub
        return null;
    }

    protected void closeDBResources(Statement st, ResultSet rs, Connection conn) {
        if (st != null) {
            try {
                st.close();
            } catch (SQLException e) {
                log.error("cannot close statement", e);
            }
        }
        if (rs != null) {
            try {
                rs.close();
            } catch (SQLException e) {
                log.error("cannot close resultset", e);
            }
        }
        if( conn != null) {
            try {
                conn.close();
            } catch (SQLException e) {
                log.error("cannot close connection", e);
            }
        }
    }

}
