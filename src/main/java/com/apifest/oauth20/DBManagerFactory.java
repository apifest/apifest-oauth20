package com.apifest.oauth20;

public class DBManagerFactory {
    private static DBManager dbManager;

    public static DBManager getInstance() {
        if (dbManager == null) {
            if("redis".equalsIgnoreCase(OAuthServer.getDatabase())) {
                dbManager = new RedisDBManager();
                ((RedisDBManager)dbManager).setupDBManager();
            }
            if("mongo".equalsIgnoreCase(OAuthServer.getDatabase())) {
                dbManager = new MongoDBManager();
            }
        }
        return dbManager;
    }

}
