package com.apifest.oauth20.persistence.cassandra;

import com.apifest.oauth20.DBManager;
import com.apifest.oauth20.AccessToken;
import com.apifest.oauth20.AuthCode;
import com.apifest.oauth20.ClientCredentials;
import com.apifest.oauth20.Scope;
import com.apifest.oauth20.ApplicationInfo;
import com.datastax.driver.core.Session;
import com.datastax.driver.core.Cluster;
import com.datastax.driver.core.ResultSet;
import com.datastax.driver.core.Row;
import com.datastax.driver.core.exceptions.NoHostAvailableException;
import com.datastax.driver.core.exceptions.QueryExecutionException;
import com.datastax.driver.core.exceptions.QueryValidationException;
import com.datastax.driver.core.querybuilder.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Created by Giovanni Baleani on 23/02/2016.
 */
public class CassandraDBManager implements DBManager {

    protected static Logger log = LoggerFactory.getLogger(DBManager.class);

    protected static final String KEYSPACE_NAME = "apifest";
    protected static final String SCOPE_TABLE_NAME = "scopes";
    protected static final String CLIENTS_TABLE_NAME = "clients";
    protected static final String AUTH_CODE_TABLE_NAME = "auth_codes";
    protected static final String ACCESS_TOKEN_TABLE_NAME = "access_tokens";


    protected static final String SCOPE_TABLE_CQL =
            "CREATE TABLE IF NOT EXISTS " + KEYSPACE_NAME + "." + SCOPE_TABLE_NAME + " (" +
            " scope text," +
            " description text," +
            " cc_expires_in int," +
            " pass_expires_in int," +
            " refresh_expires_in int," +
            " PRIMARY KEY (scope)" +
            ");";

    protected static final String CLIENTS_TABLE_CQL =
            "CREATE TABLE IF NOT EXISTS " + KEYSPACE_NAME + "." + CLIENTS_TABLE_NAME + " (" +
            " client_id text," +
            " client_secret text," +
            " scope text," +
            " name text," +
            " created timestamp," +
            " uri text," +
            " descr text," +
            " type int," +
            " status int," +
            " details MAP<text, text>," +
            " PRIMARY KEY (client_id)" +
            ");";

    protected static final String AUTH_CODE_TABLE_CQL =
            "CREATE TABLE IF NOT EXISTS " + KEYSPACE_NAME + "." + AUTH_CODE_TABLE_NAME + " (" +
            " code text," +
            " client_id text," +
            " redirect_uri text," +
            " state text," +
            " scope text," +
            " type text," +
            " valid boolean," +
            " user_id text," +
            " created timestamp," +
            " PRIMARY KEY (code)" +
            ");";

    protected static final String ACCESS_TOKEN_TABLE_CQL =
            "CREATE TABLE IF NOT EXISTS " + KEYSPACE_NAME + "." + ACCESS_TOKEN_TABLE_NAME + " (" +
                    " access_token text," +
                    " refresh_token text," +
                    " expires_in text," +
                    " scope text," +
                    " type text," +
                    " valid boolean," +
                    " client_id text," +
                    " code_id text," +
                    " user_id text," +
                    " details MAP<text, text>," +
                    " created timestamp," +
                    " refresh_expires_in text," +
                    " PRIMARY KEY (access_token)" +
                    ");";

    protected static final String REDIRECT_URI_IDX =
            "CREATE INDEX IF NOT EXISTS redirect_uri_idx ON " + KEYSPACE_NAME + "." + AUTH_CODE_TABLE_NAME +
                    " (redirect_uri);";

    private Session session;

    public CassandraDBManager(String cassandraContactPoints) {
        Cluster cluster = CassandraConnector.connect(cassandraContactPoints);
        session = cluster.connect(KEYSPACE_NAME);

        // create tables (if not exists)
        session.execute(SCOPE_TABLE_CQL);
        session.execute(CLIENTS_TABLE_CQL);
        session.execute(AUTH_CODE_TABLE_CQL);
        session.execute(ACCESS_TOKEN_TABLE_CQL);

        // create sec. indexes (if not exists)
        session.execute(REDIRECT_URI_IDX);
    }

    @Override
    protected void finalize() throws Throwable {
        CassandraConnector.close();
    }

    @Override
    public void storeAccessToken(AccessToken accessToken) {
        Insert stmt = QueryBuilder.insertInto(KEYSPACE_NAME, ACCESS_TOKEN_TABLE_NAME)
            .value("access_token", accessToken.getToken())
            .value("refresh_token", accessToken.getRefreshToken())
            .value("expires_in", accessToken.getExpiresIn())
            .value("scope", accessToken.getScope())
            .value("type", accessToken.getType())
            .value("valid", accessToken.isValid())
            .value("client_id", accessToken.getClientId())
            .value("code_id", accessToken.getCodeId())
            .value("user_id", accessToken.getUserId())
            .value("details", accessToken.getDetails())
            .value("created", accessToken.getCreated())
            .value("refresh_expires_in", accessToken.getRefreshExpiresIn())
        ;
        // TTL
        Long tokenExpiration = (accessToken.getRefreshExpiresIn() != null && !accessToken.getRefreshExpiresIn().isEmpty()) ? Long.valueOf(accessToken.getRefreshExpiresIn()) : Long.valueOf(accessToken.getExpiresIn());
        int ttl = tokenExpiration.intValue();
        stmt.using(QueryBuilder.ttl(ttl));

        try {
            session.execute(stmt);
        } catch (NoHostAvailableException e) {
            log.error("No host in the %s cluster can be contacted to execute the query.\n",
                    session.getCluster());
        } catch (QueryExecutionException e) {
            log.error("An exception was thrown by Cassandra because it cannot " +
                    "successfully execute the query with the specified consistency level.");
        } catch (QueryValidationException e) {
            log.error("The query %s \nis not valid, for example, incorrect syntax.\n",
                    stmt.getQueryString());
        } catch (IllegalStateException e) {
            log.error("The BoundStatement is not ready.");
        }
    }

    @Override
    public void updateAccessTokenValidStatus(String accessToken, boolean valid) {
        Update.Where stmt = QueryBuilder.update(KEYSPACE_NAME, ACCESS_TOKEN_TABLE_NAME)
                .with(QueryBuilder.set("valid", valid))
                .where(QueryBuilder.eq("access_token", accessToken))
                ;
        try {
            session.execute(stmt);
        } catch (NoHostAvailableException e) {
            log.error("No host in the %s cluster can be contacted to execute the query.\n",
                    session.getCluster());
        } catch (QueryExecutionException e) {
            log.error("An exception was thrown by Cassandra because it cannot " +
                    "successfully execute the query with the specified consistency level.");
        } catch (QueryValidationException e) {
            log.error("The query %s \nis not valid, for example, incorrect syntax.\n",
                    stmt.getQueryString());
        } catch (IllegalStateException e) {
            log.error("The BoundStatement is not ready.");
        }
    }

    @Override
    public AccessToken findAccessToken(String accessToken) {
        Select.Where stmt = QueryBuilder.select().from(KEYSPACE_NAME, ACCESS_TOKEN_TABLE_NAME)
                .where(QueryBuilder.eq("access_token", accessToken));
        try {
            ResultSet rs = session.execute(stmt);
            Iterator<Row> iter = rs.iterator();
            if(iter.hasNext()) {
                Row row = iter.next();
                AccessToken atoken = mapRowToAccessToken(row);
                return atoken;
            }
        } catch (NoHostAvailableException e) {
            log.error("No host in the %s cluster can be contacted to execute the query.\n",
                    session.getCluster());
        } catch (QueryExecutionException e) {
            log.error("An exception was thrown by Cassandra because it cannot " +
                    "successfully execute the query with the specified consistency level.");
        } catch (QueryValidationException e) {
            log.error("The query %s \nis not valid, for example, incorrect syntax.\n",
                    stmt.getQueryString());
        } catch (IllegalStateException e) {
            log.error("The BoundStatement is not ready.");
        }
        return null;
    }
    private AccessToken mapRowToAccessToken(Row row) {
        AccessToken atoken = new AccessToken();
        atoken.setToken(row.getString("access_token"));
        atoken.setRefreshToken(row.getString("refresh_token"));
        atoken.setExpiresIn(row.getString("expires_in"));
        atoken.setScope(row.getString("scope"));
        atoken.setType(row.getString("type"));
        atoken.setValid(row.getBool("valid"));
        atoken.setClientId(row.getString("client_id"));
        atoken.setCodeId(row.getString("code_id"));
        atoken.setUserId(row.getString("user_id"));
        atoken.setDetails(row.getMap("details", String.class, String.class));
        atoken.setCreated(row.getTimestamp("created").getTime());
        atoken.setRefreshExpiresIn(row.getString("refresh_expires_in"));
        return atoken;
    }

    @Override
    public void removeAccessToken(String accessToken) {
        Delete.Where stmt = QueryBuilder.delete().from(KEYSPACE_NAME, ACCESS_TOKEN_TABLE_NAME)
                .where(QueryBuilder.eq("access_token", accessToken));
        try {
            session.execute(stmt);
        } catch (NoHostAvailableException e) {
            log.error("No host in the %s cluster can be contacted to execute the query.\n",
                    session.getCluster());
        } catch (QueryExecutionException e) {
            log.error("An exception was thrown by Cassandra because it cannot " +
                    "successfully execute the query with the specified consistency level.");
        } catch (QueryValidationException e) {
            log.error("The query %s \nis not valid, for example, incorrect syntax.\n",
                    stmt.getQueryString());
        } catch (IllegalStateException e) {
            log.error("The BoundStatement is not ready.");
        }
    }

    @Override
    public AccessToken findAccessTokenByRefreshToken(String refreshToken, String clientId) {
        Select.Where stmt = QueryBuilder.select().from(KEYSPACE_NAME, ACCESS_TOKEN_TABLE_NAME)
                .allowFiltering() // TODO: build a materialized view with refreshToken + clientId key
                .where()
                    .and(QueryBuilder.eq("refresh_token", refreshToken))
                    .and(QueryBuilder.eq("client_id", clientId))
        ;
        try {
            ResultSet rs = session.execute(stmt);
            Iterator<Row> iter = rs.iterator();
            if(iter.hasNext()) {
                Row row = iter.next();
                AccessToken atoken = mapRowToAccessToken(row);
                log.debug(atoken.getToken());
                return atoken;
            }
        } catch (NoHostAvailableException e) {
            log.error("No host in the %s cluster can be contacted to execute the query.\n",
                    session.getCluster());
        } catch (QueryExecutionException e) {
            log.error("An exception was thrown by Cassandra because it cannot " +
                    "successfully execute the query with the specified consistency level.");
        } catch (QueryValidationException e) {
            log.error("The query %s \nis not valid, for example, incorrect syntax.\n",
                    stmt.getQueryString());
        } catch (IllegalStateException e) {
            log.error("The BoundStatement is not ready.");
        }
        return null;
    }

    @Override
    public List<AccessToken> getAccessTokenByUserIdAndClientApp(String userId, String clientId) {
        // TODO: build a materialized view with userId + clientId key
        List<AccessToken> list = new ArrayList<AccessToken>();
        Select.Where stmt = QueryBuilder.select().from(KEYSPACE_NAME, ACCESS_TOKEN_TABLE_NAME)
                .allowFiltering()
                .where()
                .and(QueryBuilder.eq("user_id", userId))
                .and(QueryBuilder.eq("client_id", clientId))
        ;
        try {
            ResultSet rs = session.execute(stmt);
            for (Row row : rs) {
                AccessToken atoken = mapRowToAccessToken(row);
                list.add(atoken);
            }
        } catch (NoHostAvailableException e) {
            log.error("No host in the %s cluster can be contacted to execute the query.\n",
                    session.getCluster());
        } catch (QueryExecutionException e) {
            log.error("An exception was thrown by Cassandra because it cannot " +
                    "successfully execute the query with the specified consistency level.");
        } catch (QueryValidationException e) {
            log.error("The query %s \nis not valid, for example, incorrect syntax.\n",
                    stmt.getQueryString());
        } catch (IllegalStateException e) {
            log.error("The BoundStatement is not ready.");
        }
        return list;
    }





    @Override
    public void storeAuthCode(AuthCode authCode) {
        Insert stmt = QueryBuilder.insertInto(KEYSPACE_NAME, AUTH_CODE_TABLE_NAME)
            .value("code", authCode.getCode())
            .value("client_id", authCode.getClientId())
            .value("redirect_uri", authCode.getRedirectUri())
            .value("state", authCode.getState())
            .value("scope", authCode.getScope())
            .value("type", authCode.getType())
            .value("valid", authCode.isValid())
            .value("user_id", authCode.getUserId())
            .value("created", authCode.getCreated())
        ;
        try {
            session.execute(stmt);
        } catch (NoHostAvailableException e) {
            log.error("No host in the %s cluster can be contacted to execute the query.\n",
                    session.getCluster());
        } catch (QueryExecutionException e) {
            log.error("An exception was thrown by Cassandra because it cannot " +
                    "successfully execute the query with the specified consistency level.");
        } catch (QueryValidationException e) {
            log.error("The query %s \nis not valid, for example, incorrect syntax.\n",
                    stmt.getQueryString());
        } catch (IllegalStateException e) {
            log.error("The BoundStatement is not ready.");
        }
    }

    @Override
    public void updateAuthCodeValidStatus(String authCode, boolean valid) {
        Update.Where stmt = QueryBuilder.update(KEYSPACE_NAME, AUTH_CODE_TABLE_NAME)
            .with(QueryBuilder.set("valid", valid))
            .where(QueryBuilder.eq("code", authCode))
        ;
        try {
            session.execute(stmt);
        } catch (NoHostAvailableException e) {
            log.error("No host in the %s cluster can be contacted to execute the query.\n",
                    session.getCluster());
        } catch (QueryExecutionException e) {
            log.error("An exception was thrown by Cassandra because it cannot " +
                    "successfully execute the query with the specified consistency level.");
        } catch (QueryValidationException e) {
            log.error("The query %s \nis not valid, for example, incorrect syntax.\n",
                    stmt.getQueryString());
        } catch (IllegalStateException e) {
            log.error("The BoundStatement is not ready.");
        }
    }

    @Override
    public AuthCode findAuthCode(String authCode, String redirectUri) {
        Select.Where stmt = QueryBuilder.select().from(KEYSPACE_NAME, AUTH_CODE_TABLE_NAME)
                .where(QueryBuilder.eq("code", authCode))
                .and(QueryBuilder.eq("redirect_uri", redirectUri));
        try {
            ResultSet rs = session.execute(stmt);
            Iterator<Row> iter = rs.iterator();
            if(iter.hasNext()) {
                Row row = iter.next();
                boolean valid = row.getBool("valid");
                if(valid) {
                    AuthCode ret = new AuthCode();
                    ret.setCode(row.getString("code"));
                    ret.setClientId(row.getString("client_id"));
                    ret.setRedirectUri(row.getString("redirect_uri"));
                    ret.setState(row.getString("state"));
                    ret.setScope(row.getString("scope"));
                    ret.setType(row.getString("type"));
                    ret.setValid(row.getBool("valid"));
                    ret.setUserId(row.getString("user_id"));
                    ret.setCreated(row.getTimestamp("created").getTime());
                    return ret;
                }
            }
        } catch (NoHostAvailableException e) {
            log.error("No host in the %s cluster can be contacted to execute the query.\n",
                    session.getCluster());
        } catch (QueryExecutionException e) {
            log.error("An exception was thrown by Cassandra because it cannot " +
                    "successfully execute the query with the specified consistency level.");
        } catch (QueryValidationException e) {
            log.error("The query %s \nis not valid, for example, incorrect syntax.\n",
                    stmt.getQueryString());
        } catch (IllegalStateException e) {
            log.error("The BoundStatement is not ready.");
        }
        return null;
    }



    @Override
    public boolean storeScope(Scope scope) {
        Insert stmt = QueryBuilder.insertInto(KEYSPACE_NAME, SCOPE_TABLE_NAME)
                .value("scope", scope.getScope())
                .value("description", scope.getDescription())
                .value("cc_expires_in", scope.getCcExpiresIn())
                .value("pass_expires_in", scope.getPassExpiresIn())
                .value("refresh_expires_in", scope.getRefreshExpiresIn())
                ;
        try {
            session.execute(stmt);
        } catch (NoHostAvailableException e) {
            log.error("No host in the %s cluster can be contacted to execute the query.\n",
                    session.getCluster());
        } catch (QueryExecutionException e) {
            log.error("An exception was thrown by Cassandra because it cannot " +
                    "successfully execute the query with the specified consistency level.");
        } catch (QueryValidationException e) {
            log.error("The query %s \nis not valid, for example, incorrect syntax.\n",
                    stmt.getQueryString());
        } catch (IllegalStateException e) {
            log.error("The BoundStatement is not ready.");
        }
        return true;
    }

    @Override
    public List<Scope> getAllScopes() {
        List<Scope> list = new ArrayList<Scope>();
        Select stmt = QueryBuilder.select().from(KEYSPACE_NAME, SCOPE_TABLE_NAME);
        try {
            ResultSet rs = session.execute(stmt);
            for (Row row : rs) {
                Scope scope = new Scope();
                scope.setScope(row.getString("scope"));
                scope.setDescription(row.getString("description"));
                scope.setCcExpiresIn(row.getInt("cc_expires_in"));
                scope.setPassExpiresIn(row.getInt("pass_expires_in"));
                scope.setRefreshExpiresIn(row.getInt("refresh_expires_in"));
                list.add(scope);
            }
        } catch (NoHostAvailableException e) {
            log.error("No host in the %s cluster can be contacted to execute the query.\n",
                    session.getCluster());
        } catch (QueryExecutionException e) {
            log.error("An exception was thrown by Cassandra because it cannot " +
                    "successfully execute the query with the specified consistency level.");
        } catch (QueryValidationException e) {
            log.error("The query %s \nis not valid, for example, incorrect syntax.\n",
                    stmt.getQueryString());
        } catch (IllegalStateException e) {
            log.error("The BoundStatement is not ready.");
        }
        return list;
    }

    @Override
    public Scope findScope(String scopeName) {
        Select.Where stmt = QueryBuilder.select().from(KEYSPACE_NAME, SCOPE_TABLE_NAME)
                .where(QueryBuilder.eq("scope", scopeName));
        try {
            ResultSet rs = session.execute(stmt);
            Iterator<Row> iter = rs.iterator();
            if(iter.hasNext()) {
                Scope scope = new Scope();
                Row row = iter.next();
                scope.setScope(row.getString("scope"));
                scope.setDescription(row.getString("description"));
                scope.setCcExpiresIn(row.getInt("cc_expires_in"));
                scope.setPassExpiresIn(row.getInt("pass_expires_in"));
                scope.setRefreshExpiresIn(row.getInt("refresh_expires_in"));
                return scope;
            }
        } catch (NoHostAvailableException e) {
            log.error("No host in the %s cluster can be contacted to execute the query.\n",
                    session.getCluster());
        } catch (QueryExecutionException e) {
            log.error("An exception was thrown by Cassandra because it cannot " +
                    "successfully execute the query with the specified consistency level.");
        } catch (QueryValidationException e) {
            log.error("The query %s \nis not valid, for example, incorrect syntax.\n",
                    stmt.getQueryString());
        } catch (IllegalStateException e) {
            log.error("The BoundStatement is not ready.");
        }
        return null;
    }

    @Override
    public boolean deleteScope(String scopeName) {
        Delete.Where stmt = QueryBuilder.delete().from(KEYSPACE_NAME, SCOPE_TABLE_NAME)
                .where(QueryBuilder.eq("scope", scopeName));
        try {
            session.execute(stmt);
        } catch (NoHostAvailableException e) {
            log.error("No host in the %s cluster can be contacted to execute the query.\n",
                    session.getCluster());
            return false;
        } catch (QueryExecutionException e) {
            log.error("An exception was thrown by Cassandra because it cannot " +
                    "successfully execute the query with the specified consistency level.");
            return false;
        } catch (QueryValidationException e) {
            log.error("The query %s \nis not valid, for example, incorrect syntax.\n",
                    stmt.getQueryString());
            return false;
        } catch (IllegalStateException e) {
            log.error("The BoundStatement is not ready.");
            return false;
        }
        return true;
    }



    @Override
    public boolean validClient(String clientId, String clientSecret) {
        Select.Where stmt = QueryBuilder.select("client_id", "client_secret", "status")
                .from(KEYSPACE_NAME, CLIENTS_TABLE_NAME)
                .where(QueryBuilder.eq("client_id", clientId));
        try {
            ResultSet rs = session.execute(stmt);
            Iterator<Row> iter = rs.iterator();
            if(iter.hasNext()) {
                Row row = iter.next();
                boolean ret = (row.getString("client_secret").equals(clientSecret)
                        && String.valueOf(ClientCredentials.ACTIVE_STATUS).equals(row.getInt("status")));
                return ret;
            }
        } catch (NoHostAvailableException e) {
            log.error("No host in the %s cluster can be contacted to execute the query.\n",
                    session.getCluster());
        } catch (QueryExecutionException e) {
            log.error("An exception was thrown by Cassandra because it cannot " +
                    "successfully execute the query with the specified consistency level.");
        } catch (QueryValidationException e) {
            log.error("The query %s \nis not valid, for example, incorrect syntax.\n",
                    stmt.getQueryString());
        } catch (IllegalStateException e) {
            log.error("The BoundStatement is not ready.");
        }
        return false;
    }
    @Override
    public ClientCredentials findClientCredentials(String clientId) {
        Select.Where stmt = QueryBuilder.select().from(KEYSPACE_NAME, CLIENTS_TABLE_NAME)
                .where(QueryBuilder.eq("client_id", clientId));
        try {
            ResultSet rs = session.execute(stmt);
            Iterator<Row> iter = rs.iterator();
            if(iter.hasNext()) {
                Row row = iter.next();
                ClientCredentials app = new ClientCredentials();
                app.setId(row.getString("client_id"));
                app.setSecret(row.getString("client_secret"));
                app.setScope(row.getString("scope"));
                app.setName(row.getString("name"));
                app.setCreated(row.getTimestamp("created").getTime());
                app.setUri(row.getString("uri"));
                app.setDescr(row.getString("descr"));
                app.setType(row.getInt("type"));
                app.setStatus(row.getInt("status"));
                app.setApplicationDetails(row.getMap("details", String.class, String.class));
                return app;
            }
        } catch (NoHostAvailableException e) {
            log.error("No host in the %s cluster can be contacted to execute the query.\n",
                    session.getCluster());
        } catch (QueryExecutionException e) {
            log.error("An exception was thrown by Cassandra because it cannot " +
                    "successfully execute the query with the specified consistency level.");
        } catch (QueryValidationException e) {
            log.error("The query %s \nis not valid, for example, incorrect syntax.\n",
                    stmt.getQueryString());
        } catch (IllegalStateException e) {
            log.error("The BoundStatement is not ready.");
        }
        return null;
    }

    @Override
    public void storeClientCredentials(ClientCredentials clientCreds) {
        Insert stmt = QueryBuilder.insertInto(KEYSPACE_NAME, CLIENTS_TABLE_NAME)
            .value("client_id", clientCreds.getId())
                .value("client_secret", clientCreds.getSecret())
                .value("scope", clientCreds.getScope())
                .value("name", clientCreds.getName())
                .value("created", clientCreds.getCreated())
                .value("uri", clientCreds.getUri())
                .value("descr", clientCreds.getDescr())
                .value("type", clientCreds.getType())
                .value("status", clientCreds.getStatus())
                .value("details", clientCreds.getApplicationDetails());
        try {
            session.execute(stmt);
        } catch (NoHostAvailableException e) {
            log.error("No host in the %s cluster can be contacted to execute the query.\n",
                    session.getCluster());
        } catch (QueryExecutionException e) {
            log.error("An exception was thrown by Cassandra because it cannot " +
                    "successfully execute the query with the specified consistency level.");
        } catch (QueryValidationException e) {
            log.error("The query %s \nis not valid, for example, incorrect syntax.\n",
                    stmt.getQueryString());
        } catch (IllegalStateException e) {
            log.error("The BoundStatement is not ready.");
        }
    }


    @Override
    public boolean updateClientApp(String clientId, String scope, String description, Integer status, Map<String, String> applicationDetails) {
        Update update = QueryBuilder.update(KEYSPACE_NAME, CLIENTS_TABLE_NAME);
        Update.Assignments assignments = update.with();
        if (scope != null && scope.length() > 0) {
            assignments.and(QueryBuilder.set("scope", scope));
        }
        if (description != null && description.length() > 0) {
            assignments.and(QueryBuilder.set("descr", description));
        }
        if (status != null) {
            assignments.and(QueryBuilder.set("status", status));
        }
        if (applicationDetails != null && applicationDetails.size() > 0) {
            assignments.and(QueryBuilder.set("details", applicationDetails));
        }
        Update.Where stmt = assignments.where(QueryBuilder.eq("client_id", clientId));
        try {
            session.execute(stmt);
            return true;
        } catch (NoHostAvailableException e) {
            log.error("No host in the %s cluster can be contacted to execute the query.\n",
                    session.getCluster());
        } catch (QueryExecutionException e) {
            log.error("An exception was thrown by Cassandra because it cannot " +
                    "successfully execute the query with the specified consistency level.");
        } catch (QueryValidationException e) {
            log.error("The query %s \nis not valid, for example, incorrect syntax.\n",
                    stmt.getQueryString());
        } catch (IllegalStateException e) {
            log.error("The BoundStatement is not ready.");
        }
        return false;
    }



    @Override
    public List<ApplicationInfo> getAllApplications() {
        List<ApplicationInfo> list = new ArrayList<ApplicationInfo>();
        Select stmt = QueryBuilder.select().from(KEYSPACE_NAME, CLIENTS_TABLE_NAME);
        try {
            ResultSet rs = session.execute(stmt);
            for (Row row : rs) {
                ApplicationInfo app = new ApplicationInfo();
                app.setId(row.getString("client_id"));
                app.setSecret(row.getString("client_secret"));
                app.setScope(row.getString("scope"));
                app.setName(row.getString("name"));
                app.setRegistered(row.getTimestamp("created"));
                app.setRedirectUri(row.getString("uri"));
                app.setDescription(row.getString("descr"));
                app.setStatus(row.getInt("status"));
                app.setApplicationDetails(row.getMap("details", String.class, String.class));
                list.add(app);
            }
        } catch (NoHostAvailableException e) {
            log.error("No host in the %s cluster can be contacted to execute the query.\n",
                    session.getCluster());
        } catch (QueryExecutionException e) {
            log.error("An exception was thrown by Cassandra because it cannot " +
                    "successfully execute the query with the specified consistency level.");
        } catch (QueryValidationException e) {
            log.error("The query %s \nis not valid, for example, incorrect syntax.\n",
                    stmt.getQueryString());
        } catch (IllegalStateException e) {
            log.error("The BoundStatement is not ready.");
        }
        return list;
    }

}
