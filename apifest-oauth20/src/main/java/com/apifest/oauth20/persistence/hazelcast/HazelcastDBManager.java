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

package com.apifest.oauth20.persistence.hazelcast;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.apifest.oauth20.AccessToken;
import com.apifest.oauth20.ApplicationInfo;
import com.apifest.oauth20.AuthCode;
import com.apifest.oauth20.ClientCredentials;
import com.apifest.oauth20.DBManager;
import com.apifest.oauth20.OAuthServer;
import com.apifest.oauth20.Scope;
import com.hazelcast.config.Config;
import com.hazelcast.config.ExecutorConfig;
import com.hazelcast.config.GroupConfig;
import com.hazelcast.config.InMemoryFormat;
import com.hazelcast.config.InterfacesConfig;
import com.hazelcast.config.JoinConfig;
import com.hazelcast.config.MapConfig;
import com.hazelcast.config.MaxSizeConfig;
import com.hazelcast.config.MulticastConfig;
import com.hazelcast.config.NetworkConfig;
import com.hazelcast.config.TcpIpConfig;
import com.hazelcast.config.MapConfig.EvictionPolicy;
import com.hazelcast.config.MaxSizeConfig.MaxSizePolicy;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import com.hazelcast.query.EntryObject;
import com.hazelcast.query.Predicate;
import com.hazelcast.query.PredicateBuilder;

/**
 * This class implements a persistent storage layer using the Hazelcast Cache.
 *
 * @author Apostol Terziev
 *
 */
public class HazelcastDBManager implements DBManager {

    protected static Logger log = LoggerFactory.getLogger(HazelcastDBManager.class);

    private static final String APIFEST_SCOPE = "APIFEST_SCOPE";
    private static final String APIFEST_CLIENT = "APIFEST_CLIENT";
    private static final String APIFEST_AUTH_CODE = "APIFEST_AUTH_CODE";
    private static final String APIFEST_ACCESS_TOKEN = "APIFEST_ACCESS_TOKEN";
    private static HazelcastInstance hazelcastClient = null;

    private static final int MAX_POOL_SIZE = 64;

    static {
        // REVISIT: Hazelcast configuration
        Config config = createConfiguration();
        GroupConfig groupConfig = new GroupConfig("apifest-oauth20", OAuthServer.getHazelcastPassword());
        config.setGroupConfig(groupConfig);
        config.setMapConfigs(createMapConfigs());
        hazelcastClient = Hazelcast.newHazelcastInstance(config);
        hazelcastClient.getMap(APIFEST_AUTH_CODE).addIndex("codeURI", false);
        hazelcastClient.getMap(APIFEST_ACCESS_TOKEN).addIndex("refreshTokenByClient", false);
        hazelcastClient.getMap(APIFEST_ACCESS_TOKEN).addIndex("accessTokenByUserIdAndClient", false);
    }

    private static Map<String, MapConfig> createMapConfigs() {
        Map<String, MapConfig> configs = new HashMap<String, MapConfig>();
        MapConfig accTokenConfig = createMapConfig(APIFEST_ACCESS_TOKEN);
        MapConfig scopeConfig = createMapConfig(APIFEST_SCOPE);
        MapConfig clientConfig = createMapConfig(APIFEST_CLIENT);
        MapConfig authCodeConfig = createMapConfig(APIFEST_AUTH_CODE);
        configs.put(accTokenConfig.getName(), accTokenConfig);
        configs.put(scopeConfig.getName(), scopeConfig);
        configs.put(clientConfig.getName(), clientConfig);
        configs.put(authCodeConfig.getName(), authCodeConfig);
        return configs;
    }

    private static MapConfig createMapConfig(String mapName) {
        MapConfig mapConfig = new MapConfig(mapName);
        mapConfig.setInMemoryFormat(InMemoryFormat.OBJECT);
        mapConfig.setBackupCount(1);
        mapConfig.setEvictionPolicy(EvictionPolicy.NONE);
        mapConfig.setMaxSizeConfig(new MaxSizeConfig(0, MaxSizePolicy.PER_NODE));
        mapConfig.setEvictionPercentage(0);
        mapConfig.setMergePolicy("com.hazelcast.map.merge.PutIfAbsentMapMergePolicy");
        return mapConfig;
    }

    private static Config createConfiguration() {
        Config config = new Config();
        NetworkConfig networkCfg = createNetworkConfigs();
        config.setNetworkConfig(networkCfg);

        ExecutorConfig executorConfig = new ExecutorConfig();
        executorConfig.setPoolSize(MAX_POOL_SIZE);
        executorConfig.setStatisticsEnabled(false);
        config.addExecutorConfig(executorConfig);

        return config;
    }

    private static NetworkConfig createNetworkConfigs() {
        NetworkConfig networkConfig = new NetworkConfig();
        InterfacesConfig interfaceConfig = new InterfacesConfig();
        // add current host
        try {
            interfaceConfig.addInterface(InetAddress.getByName(OAuthServer.getHost()).getHostAddress());
        } catch (UnknownHostException e) {
            log.error("cannot create hazelcast config", e);
        }
        interfaceConfig.setEnabled(true);

        networkConfig.setInterfaces(interfaceConfig);
        JoinConfig joinConfig = new JoinConfig();
        TcpIpConfig tcpIps = new TcpIpConfig();

        List<String> ips = createNodesList();
        if (ips != null) {
            tcpIps.setMembers(ips);
            joinConfig.setTcpIpConfig(tcpIps);
        }
        tcpIps.setEnabled(true);

        MulticastConfig multicastConfig = new MulticastConfig();
        multicastConfig.setEnabled(false);
        joinConfig.setMulticastConfig(multicastConfig);
        networkConfig.setJoin(joinConfig);

        return networkConfig;
    }

    private static List<String> createNodesList() {
        List<String> nodes = null;
        String list = OAuthServer.getApifestOAuth20Nodes();
        if (list != null && list.length() > 0) {
            String [] n = list.split(",");
            nodes = Arrays.asList(n);
        }
        return nodes;
    }

    /*
     * @see com.apifest.oauth20.DBManager#validClient(java.lang.String, java.lang.String)
     */
    @Override
    public boolean validClient(String clientId, String clientSecret) {
        ClientCredentials clientCredentials = findClientCredentials(clientId);
        if (clientCredentials != null && clientCredentials.getSecret().equals(clientSecret) && clientCredentials.getStatus() == ClientCredentials.ACTIVE_STATUS) {
            return true;
        }
        return false;
    }

    /*
     * @see com.apifest.oauth20.DBManager#storeClientCredentials(com.apifest.oauth20.ClientCredentials)
     */
    @Override
    public void storeClientCredentials(ClientCredentials clientCreds) {
        getClientCredentialsContainer().put(clientCreds.getId(),
                PersistenceTransformations.toPersistentClientCredentials(clientCreds));
    }

    /*
     * @see com.apifest.oauth20.DBManager#storeAuthCode(com.apifest.oauth20.AuthCode)
     */
    // TODO: Set expiration time for auth code
    @Override
    public void storeAuthCode(AuthCode authCode) {
        getAuthCodeContainer().put(authCode.getCode(), PersistenceTransformations.toPersistentAuthCode(authCode));
    }

    /*
     * @see com.apifest.oauth20.DBManager#updateAuthCodeValidStatus(java.lang.String, boolean)
     */
    @Override
    public void updateAuthCodeValidStatus(String authCode, boolean valid) {
        PersistentAuthCode persistentAuthCode = getAuthCodeContainer().get(authCode);
        persistentAuthCode.setValid(valid);
        getAuthCodeContainer().put(authCode, persistentAuthCode);
    }

    /*
     * @see com.apifest.oauth20.DBManager#storeAccessToken(com.apifest.oauth20.AccessToken)
     */
    @Override
    public void storeAccessToken(AccessToken accessToken) {
        Long tokenExpiration = (accessToken.getRefreshExpiresIn() != null && !accessToken.getRefreshExpiresIn().isEmpty()) ? Long.valueOf(accessToken.getRefreshExpiresIn()) : Long.valueOf(accessToken.getExpiresIn());
        getAccessTokenContainer().put(accessToken.getToken(), PersistenceTransformations.toPersistentAccessToken(accessToken),
                tokenExpiration, TimeUnit.SECONDS);
    }

    /*
     * @see com.apifest.oauth20.DBManager#findAccessTokenByRefreshToken(java.lang.String, java.lang.String)
     */
    @Override
    @SuppressWarnings("unchecked")
    public AccessToken findAccessTokenByRefreshToken(String refreshToken, String clientId) {
        EntryObject eo = new PredicateBuilder().getEntryObject();
        Predicate<String, String> predicate = eo.get("refreshTokenByClient").equal(refreshToken + clientId);
        Collection<PersistentAccessToken> values = getAccessTokenContainer().values(predicate);
        if (values.isEmpty()) {
            return null;
        }
        return PersistenceTransformations.toAccessToken(values.iterator().next());
    }

    /*
     * @see com.apifest.oauth20.DBManager#updateAccessTokenValidStatus(java.lang.String, boolean)
     */
    @Override
    public void updateAccessTokenValidStatus(String accessToken, boolean valid) {
        PersistentAccessToken persistentAccessToken = getAccessTokenContainer().get(accessToken);
        persistentAccessToken.setValid(valid);
        getAccessTokenContainer().put(accessToken, persistentAccessToken);
    }

    /*
     * @see com.apifest.oauth20.DBManager#findAccessToken(java.lang.String)
     */
    @Override
    public AccessToken findAccessToken(String accessToken) {
        PersistentAccessToken tokenStored = getAccessTokenContainer().get(accessToken);
        if (tokenStored != null) {
            return PersistenceTransformations.toAccessToken(tokenStored);
        } else {
            return null;
        }
    }

    /*
     * @see com.apifest.oauth20.DBManager#findAuthCode(java.lang.String, java.lang.String)
     */
    @Override
    @SuppressWarnings("unchecked")
    public AuthCode findAuthCode(String authCode, String redirectUri) {
        EntryObject eo = new PredicateBuilder().getEntryObject();
        Predicate<String, String> predicate = eo.get("codeURI").equal(authCode + redirectUri + true);
        Collection<PersistentAuthCode> values = getAuthCodeContainer().values(predicate);
        if (values.isEmpty()) {
            return null;
        }
        return PersistenceTransformations.toAuthCode(values.iterator().next());
    }

    /*
     * @see com.apifest.oauth20.DBManager#findClientCredentials(java.lang.String)
     */
    @Override
    public ClientCredentials findClientCredentials(String clientId) {
        return PersistenceTransformations.toClientCredentials(getClientCredentialsContainer().get(clientId));
    }

    /*
     * @see com.apifest.oauth20.DBManager#storeScope(com.apifest.oauth20.Scope)
     */
    @Override
    public boolean storeScope(Scope scope) {
        getScopesContainer().put(scope.getScope(), PersistenceTransformations.toPersistentScope(scope));
        return true;
    }

    /*
     * @see com.apifest.oauth20.DBManager#getAllScopes()
     */
    @Override
    public List<Scope> getAllScopes() {
        List<Scope> scopesList = new ArrayList<Scope>();
        IMap<String, PersistentScope> scopesContainer = getScopesContainer();
        for (String key : scopesContainer.keySet()) {
            scopesList.add(PersistenceTransformations.toScope(scopesContainer.get(key)));
        }
        return scopesList;
    }

    /*
     * @see com.apifest.oauth20.DBManager#findScope(java.lang.String)
     */
    @Override
    public Scope findScope(String scopeName) {
        return PersistenceTransformations.toScope(getScopesContainer().get(scopeName));
    }

    private IMap<String, PersistentScope> getScopesContainer() {
        return hazelcastClient.getMap(APIFEST_SCOPE);
    }

    private IMap<String, PersistentClientCredentials> getClientCredentialsContainer() {
        return hazelcastClient.getMap(APIFEST_CLIENT);
    }

    private IMap<String, PersistentAuthCode> getAuthCodeContainer() {
        return hazelcastClient.getMap(APIFEST_AUTH_CODE);
    }

    private IMap<String, PersistentAccessToken> getAccessTokenContainer() {
        return hazelcastClient.getMap(APIFEST_ACCESS_TOKEN);
    }

    /*
     * @see com.apifest.oauth20.DBManager#updateClientAppScope(java.lang.String)
     */
    @Override
    public boolean updateClientApp(String clientId, String scope, String description, Integer status, Map<String, String> applicationDetails) {
        PersistentClientCredentials clientCredentials = getClientCredentialsContainer().get(clientId);
        if (scope != null && scope.length() > 0) {
            clientCredentials.setScope(scope);
        }
        if (description != null && description.length() > 0) {
            clientCredentials.setDescr(description);
        }
        if (status != null) {
            clientCredentials.setStatus(status);
        }
        if (applicationDetails != null) {
            clientCredentials.setApplicationDetails(applicationDetails);
        }
        getClientCredentialsContainer().put(clientId, clientCredentials);
        return true;
    }

    /*
     * @see com.apifest.oauth20.DBManager#getAllApplications()
     */
    @Override
    public List<ApplicationInfo> getAllApplications() {
        List<ApplicationInfo> appsList = new ArrayList<ApplicationInfo>();
        IMap<String, PersistentClientCredentials> clientsContainer = getClientCredentialsContainer();
        for (String key : clientsContainer.keySet()) {
            ApplicationInfo appInfo = PersistenceTransformations.toApplicationInfo(clientsContainer.get(key));
            appsList.add(appInfo);
        }
        return appsList;
    }

    /*
     * @see com.apifest.oauth20.DBManager#deleteScope(java.lang.String)
     */
    @Override
    public boolean deleteScope(String scopeName) {
        PersistentScope scope = getScopesContainer().remove(scopeName);
        return (scope != null) ? true : false;
    }

    /*
     * @see com.apifest.oauth20.DBManager#getAccessTokenByUserIdAndClientApp(java.lang.String, java.lang.String)
     */
    @Override
    @SuppressWarnings("unchecked")
    public List<AccessToken> getAccessTokenByUserIdAndClientApp(String userId, String clientId) {
        List<AccessToken> accessTokens = new ArrayList<AccessToken>();
        EntryObject eo = new PredicateBuilder().getEntryObject();
        Predicate<String, String> predicate = eo.get("accessTokenByUserIdAndClient").equal(userId + clientId + true);
        Collection<PersistentAccessToken> values = getAccessTokenContainer().values(predicate);
        if (!values.isEmpty()) {
            for (PersistentAccessToken token : values) {
                accessTokens.add(PersistenceTransformations.toAccessToken(token));
            }
        }
        return accessTokens;
    }

    @Override
    public void removeAccessToken(String accessToken) {
        getAccessTokenContainer().remove(accessToken);
    }

}
