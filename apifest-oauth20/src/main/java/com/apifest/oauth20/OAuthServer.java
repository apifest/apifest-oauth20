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
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
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

import com.apifest.oauth20.api.ICustomGrantTypeHandler;
import com.apifest.oauth20.api.IUserAuthentication;

/**
 * Class responsible for ApiFest OAuth 2.0 Server.
 *
 * @author Rossitsa Borissova
 */
public final class OAuthServer {

    protected static final Integer DEFAULT_APIFEST_OAUTH_PORT = 8080;
    protected static final String DEFAULT_APIFEST_OAUTH_HOST = "localhost";
    protected static final String DEFAULT_HAZELCAST_PASS = "dev-pass";

    private static String customJar;
    private static String userAuthClass;
    private static Class<IUserAuthentication> userAuthenticationClass;
    private static String customGrantType;
    private static String customGrantTypeClass;
    private static Class<ICustomGrantTypeHandler> customGrantTypeHandler;
    private static String host;
    private static int port;
    private static String dbURI;
    private static String database;
    private static String redisSentinels;
    private static String redisMaster;
    private static String apifestOAuth20Nodes;
    private static URLClassLoader jarClassLoader;
    private static String hazelcastPassword;

    private static String cassandraContactPoints;

    // expires_in in sec for grant type password
    public static final int DEFAULT_PASSWORD_EXPIRES_IN = 900;

    // expires_in in sec for grant type client_credentials
    public static final int DEFAULT_CC_EXPIRES_IN = 1800;

    static Logger log = LoggerFactory.getLogger(OAuthServer.class);

    private OAuthServer() {
    }

    public static void main(String[] args) {
        if (!loadConfig()) {
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

        bootstrap.bind(new InetSocketAddress(host, port));
        log.info("ApiFest OAuth 2.0 Server started at " + host + ":" + port);
    }

    protected static boolean loadConfig() {
        String propertiesFilePath = System.getProperty("properties.file");
        InputStream in = null;
        boolean loaded = false;
        try {
            if (propertiesFilePath == null) {
                in = Thread.currentThread().getContextClassLoader().getResourceAsStream("apifest-oauth.properties");
                if (in != null) {
                    loadProperties(in);
                    loaded = true;
                } else {
                    log.warn("No properties file setup, default configs will be used");
                    setDefaultConfigs();
                    loaded = true;
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

        if (DBManagerFactory.MONGO_DB.equalsIgnoreCase(database) && (dbURI == null || dbURI.isEmpty())) {
            loaded = false;
            log.error("no value set for db_uri");
        }

        if (DBManagerFactory.REDIS_DB.equalsIgnoreCase(database)) {
            if (redisMaster == null || redisMaster.isEmpty()) {
                loaded = false;
                log.error("no value set for redis.master");
            }
            if (redisSentinels == null || redisSentinels.isEmpty()) {
                loaded = false;
                log.error("no value set for redis.sentinels");
            }
        }

        if (customJar == null || customJar.isEmpty()) {
            log.warn("Set value for user_authenticate_jar in properties file, otherwise user authentication will always pass successfully");
        } else {
            loadCustomProperties();
            if (userAuthClass != null && userAuthClass.length() > 0) {
                try {
                    userAuthenticationClass = loadCustomUserAuthentication(userAuthClass);
                } catch (ClassNotFoundException e) {
                    log.error("cannot load user.authenticate.class, check property value", e);
                }
            }
            if (customGrantType != null && customGrantType.length() > 0) {
                if (customGrantTypeClass == null || customGrantTypeClass.length() == 0) {
                    loaded = false;
                    log.error("no custom.grant_type.class set for custom.grant_type={}", customGrantType);
                } else {
                    try {
                        customGrantTypeHandler = loadCustomGrantTypeClass(customGrantTypeClass);
                    } catch (ClassNotFoundException e) {
                        log.error("cannot load custom.grant_type.class, check property value", e);
                    }

                }
            }

            try {
                LifecycleEventHandlers.loadLifecycleHandlers(getJarClassLoader(), customJar);
            } catch (MalformedURLException e) {
                log.warn("cannot load custom jar");
            }
        }

        return loaded;
    }

    @SuppressWarnings("unchecked")
    public static Class<IUserAuthentication> loadCustomUserAuthentication(String className)
            throws ClassNotFoundException {
        Class<IUserAuthentication> result = null;
        try {
            URLClassLoader classLoader = getJarClassLoader();
            if (classLoader != null) {
                Class<?> clazz = classLoader.loadClass(className);
                if (IUserAuthentication.class.isAssignableFrom(clazz)) {
                    result = (Class<IUserAuthentication>) clazz;
                } else {
                    log.error(
                            "user.authentication.class {} does not implement IUserAuthentication interface, default authentication will be used",
                            clazz);
                }
            } else {
                log.error("cannot load custom jar, default authentication will be used");
            }
        } catch (MalformedURLException e) {
            log.error("cannot load custom jar, default authentication will be used");
        } catch (IllegalArgumentException e) {
            log.error(e.getMessage());
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    public static Class<ICustomGrantTypeHandler> loadCustomGrantTypeClass(String className)
            throws ClassNotFoundException {
        Class<ICustomGrantTypeHandler> result = null;
        try {
            URLClassLoader classLoader = getJarClassLoader();
            if (classLoader != null) {
                Class<?> clazz = classLoader.loadClass(className);
                if (ICustomGrantTypeHandler.class.isAssignableFrom(clazz)) {
                    result = (Class<ICustomGrantTypeHandler>) clazz;
                } else {
                    log.error("custom.grant_type.class {} does not implement ICustomGrantTypeHandler interface", clazz);
                }
            } else {
                log.error("cannot load custom jar");
            }
        } catch (MalformedURLException e) {
            log.error("cannot load custom jar");
        } catch (IllegalArgumentException e) {
            log.error(e.getMessage());
        }
        return result;
    }

    protected static void loadCustomProperties() {
        Properties properties = new Properties();
        InputStream in = null;
        File file = new File(customJar + ".properties");
        if (file.exists()) {
            try {
                in = new FileInputStream(file);
                properties.load(in);
            } catch (FileNotFoundException e) {
                log.info("Cannot find custom properties file");
            } catch (IOException e) {
                log.error("Error loading custom properties file");
            } finally {
                if (in != null) {
                    try {
                        in.close();
                    } catch (IOException e) {
                        log.error("Error closing input stream", e);
                    }
                }
            }
        }
        new ResourceBundleImpl(properties).install();
    }

    private static URLClassLoader getJarClassLoader() throws MalformedURLException {
        if (jarClassLoader == null) {
            if (customJar != null) {
                File file = new File(customJar);
                if (file.exists()) {
                    URL jarfile = file.toURI().toURL();
                    jarClassLoader = URLClassLoader.newInstance(new URL[] { jarfile },
                            OAuthServer.class.getClassLoader());
                } else {
                    throw new IllegalArgumentException(
                            "check property custom.classes.jar, jar does not exist, default authentication will be used");
                }
            }
        }
        return jarClassLoader;
    }

    protected static void loadProperties(InputStream in) {
        Properties props = new Properties();
        try {
            props.load(in);
            customJar = props.getProperty("custom.classes.jar");
            userAuthClass = props.getProperty("user.authenticate.class");
            customGrantType = props.getProperty("custom.grant_type");
            customGrantTypeClass = props.getProperty("custom.grant_type.class");
            database = props.getProperty("oauth20.database", DBManagerFactory.DEFAULT_DB);
            redisSentinels = props.getProperty("redis.sentinels");
            redisMaster = props.getProperty("redis.master");
            dbURI = props.getProperty("db_uri");
            setHostAndPort((String) props.get("oauth20.host"), (String) props.get("oauth20.port"));

            apifestOAuth20Nodes = props.getProperty("apifest-oauth20.nodes");
            if (apifestOAuth20Nodes == null || apifestOAuth20Nodes.isEmpty()) {
                apifestOAuth20Nodes = DEFAULT_APIFEST_OAUTH_HOST;
            }

            // dev-pass is the default password used in Hazelcast
            hazelcastPassword = props.getProperty("hazelcast.password", "dev-pass");

            cassandraContactPoints = props.getProperty("cassandra.contanctPoints");
        } catch (IOException e) {
            log.error("Cannot load properties file", e);
        }
    }

    protected static void setHostAndPort(String configHost, String configPort) {
        host = configHost;
        // if not set in properties file, set default value
        if (host == null || host.isEmpty()) {
            host = DEFAULT_APIFEST_OAUTH_HOST;
        }
        String portStr = configPort;
        // if not set in properties file, set default value
        if (portStr == null || portStr.isEmpty()) {
            port = DEFAULT_APIFEST_OAUTH_PORT;
        } else {
            try {
                port = Integer.parseInt(portStr);
            } catch (NumberFormatException e) {
                log.error("oauth20.port must be integer");
                System.exit(1);
            }
        }
    }

    protected static void setDefaultConfigs() {
        host = DEFAULT_APIFEST_OAUTH_HOST;
        port = DEFAULT_APIFEST_OAUTH_PORT;
        apifestOAuth20Nodes = DEFAULT_APIFEST_OAUTH_HOST;
        hazelcastPassword = DEFAULT_HAZELCAST_PASS;
    }

    public static String getHost() {
        return host;
    }

    public static String getDbURI() {
        return dbURI;
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

    public static Class<IUserAuthentication> getUserAuthenticationClass() {
        return userAuthenticationClass;
    }

    public static String getCustomGrantType() {
        return customGrantType;
    }

    public static Class<ICustomGrantTypeHandler> getCustomGrantTypeHandler() {
        return customGrantTypeHandler;
    }

    public static String getHazelcastPassword() {
        return hazelcastPassword;
    }

    public static String getCassandraContactPoints() {
        return cassandraContactPoints;
    }
}
