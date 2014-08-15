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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.util.Properties;
import java.util.concurrent.Executors;

import org.jboss.netty.bootstrap.ServerBootstrap;
import org.jboss.netty.channel.ChannelFactory;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.socket.nio.NioServerSocketChannelFactory;
import org.jboss.netty.handler.codec.http.HttpChunkAggregator;
import org.jboss.netty.handler.codec.http.HttpRequestDecoder;
import org.jboss.netty.handler.codec.http.HttpResponseEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class responsible for ApiFest OAuth 2.0 Server.
 *
 * @author Rossitsa Borissova
 */
public final class OAuthServer {

    private static String userAuthEndpoint;
    private static String userIdJsonName;
    private static String host;
    private static int portInt;
    private static String dbHost;
    private static String database;
    private static String redisSentinels;
    private static String redisMaster;
    private static String apifestOAuth20Nodes;

    //expires_in in sec for grant type password
    public static final int DEFAULT_PASSWORD_EXPIRES_IN = 900;

    //expires_in in sec for grant type client_credentials
    public static final int DEFAULT_CC_EXPIRES_IN = 1800;

    private static Logger log = LoggerFactory.getLogger(OAuthServer.class);

    private OAuthServer() {
    }

    public static void main(String[] args) {
        if(!loadConfig()){
            System.exit(1);
        }

        DBManagerFactory.init();
        ChannelFactory factory = new NioServerSocketChannelFactory(Executors.newCachedThreadPool(),
                Executors.newCachedThreadPool());

        ServerBootstrap bootstrap = new ServerBootstrap(factory);
        bootstrap.setPipelineFactory(new ChannelPipelineFactory() {

            @Override
            public ChannelPipeline getPipeline() {
                ChannelPipeline pipeline = Channels.pipeline();
                pipeline.addLast("decoder", new HttpRequestDecoder());
                pipeline.addLast("aggregator", new HttpChunkAggregator(4096));
                pipeline.addLast("encoder", new HttpResponseEncoder());
                pipeline.addLast("handler", new HttpRequestHandler());
                return pipeline;
            }
        });

        bootstrap.setOption("child.tcpNoDelay", true);
        bootstrap.setOption("child.keepAlive", true);
        bootstrap.setOption("child.soLinger", -1);

        bootstrap.bind(new InetSocketAddress(host, portInt));
        log.info("ApiFest OAuth 2.0 Server started at " + host + ":" + portInt);
    }

    protected static boolean loadConfig() {
        String propertiesFilePath = System.getProperty("properties.file");
        InputStream in = null;
        boolean loaded = false;
        try {
            if (propertiesFilePath == null) {
                in = Thread.currentThread().getContextClassLoader().getResourceAsStream("apifest-oauth.properties");
                if(in != null) {
                    loadProperties(in);
                    loaded = true;
                } else {
                    log.error("Cannot load properties file");
                    return false;
                }
            } else {
                File file = new File(propertiesFilePath);
                try {
                    in = new FileInputStream(file);
                    loadProperties(in);
                    loaded = true;
                } catch (FileNotFoundException e) {
                    log.error("Cannot find properties file {}", propertiesFilePath);
                    return false;
                }
            }
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    log.error("cannot close input stream", e);
                }
            }
        }
        if(userAuthEndpoint == null) {
            loaded = false;
            log.error("Set value for user_authenticate_endpoint in properties file");
        }
        return loaded;
    }

    protected static void loadProperties(InputStream in){
        Properties props = new Properties();
        try {
            props.load(in);
            userAuthEndpoint = props.getProperty("user.authenticate.endpoint");
            userIdJsonName =  props.getProperty("user_id.name");
            database = props.getProperty("oauth20.database");
            redisSentinels = props.getProperty("redis.sentinels");
            redisMaster = props.getProperty("redis.master");
            if(userIdJsonName == null) {
                userIdJsonName = "user_id";
            }
            dbHost = props.getProperty("db_host");
            if(dbHost == null || dbHost.length() == 0) {
                dbHost = "localhost";
            }
            setHostAndPort((String) props.get("oauth20.host"), (String) props.get("oauth20.port"));
            apifestOAuth20Nodes = props.getProperty("apifest-oauth20.nodes");
        } catch (IOException e) {
            log.error("Cannot load properties file", e);
        }
    }

    protected static void setHostAndPort(String configHost, String configPort){
        host = configHost;
        // if not set in properties file, loaded from env var
        if(host == null || host.length() == 0) {
            host = System.getProperty("oauth20.host");
            if(host == null || host.length() == 0) {
                log.error("oauth20.host property not set");
                System.exit(1);
            }
        }
        String portStr = configPort;
        // if not set in properties file, loaded from env var
        if(portStr == null || portStr.length() == 0) {
            portStr = System.getProperty("oauth20.port");
            if(portStr == null || portStr.length() == 0) {
                log.error("oauth20.port property not set");
                System.exit(1);
            }
        }
        try {
            portInt = Integer.parseInt(portStr);
        } catch (NumberFormatException e) {
            log.error("oauth20.port must be integer");
            System.exit(1);
        }
    }

    public static String getHost() {
        return host;
    }

    public static String getUserAuthEndpoint() {
        return userAuthEndpoint;
    }

    public static String getUserIdJsonName (){
        return userIdJsonName;
    }

    public static String getDbHost() {
        return dbHost;
    }

    public static String getDatabase() {
        return database;
    }

    public static String getRedisSentinels() {
        return redisSentinels;
    }

    public static String getRedisMaster() {
        return redisMaster;
    }

    public static String getApifestOAuth20Nodes() {
        return apifestOAuth20Nodes;
    }
}