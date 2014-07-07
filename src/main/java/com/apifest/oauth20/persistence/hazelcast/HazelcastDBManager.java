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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.apifest.oauth20.AccessToken;
import com.apifest.oauth20.AuthCode;
import com.apifest.oauth20.ClientCredentials;
import com.apifest.oauth20.DBManager;
import com.apifest.oauth20.OAuthServer;
import com.apifest.oauth20.Scope;
import com.hazelcast.config.Config;
import com.hazelcast.config.ExecutorConfig;
import com.hazelcast.config.GroupConfig;
import com.hazelcast.config.InterfacesConfig;
import com.hazelcast.config.JoinConfig;
import com.hazelcast.config.MulticastConfig;
import com.hazelcast.config.NetworkConfig;
import com.hazelcast.config.TcpIpConfig;
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
        GroupConfig groupConfig = new GroupConfig("apifest-oauth20", "apifest-oauth20-pass");
        config.setGroupConfig(groupConfig);
        hazelcastClient = Hazelcast.newHazelcastInstance(config);
        hazelcastClient.getMap(APIFEST_AUTH_CODE).addIndex("codeURI", false);
        hazelcastClient.getMap(APIFEST_ACCESS_TOKEN).addIndex("refreshTokenByClient", false);
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
        interfaceConfig.addInterface(OAuthServer.getHost());
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

    @Override
    public boolean validClient(String clientId, String clientSecret) {
        ClientCredentials clientCredentials = findClientCredentials(clientId);
        if (clientCredentials != null && clientCredentials.getSecret().equals(clientSecret)) {
            return true;
        }
        return false;
    }

    @Override
    public void storeClientCredentials(ClientCredentials clientCreds) {
        getClientCredentialsContainer().put(clientCreds.getId(),
                PersistenceTransformations.toPersistentClientCredentials(clientCreds));
    }

    @Override
    public void storeAuthCode(AuthCode authCode) {
        getAuthCodeContainer().put(authCode.getCode(), PersistenceTransformations.toPersistentAuthCode(authCode));
    }

    @Override
    public void updateAuthCodeValidStatus(String authCode, boolean valid) {
        PersistentAuthCode persistentAuthCode = getAuthCodeContainer().get(authCode);
        persistentAuthCode.setValid(valid);
        getAuthCodeContainer().put(authCode, persistentAuthCode);
    }

    @Override
    public void storeAccessToken(AccessToken accessToken) {
        getAccessTokenContainer().put(accessToken.getToken(), PersistenceTransformations.toPersistentAccessToken(accessToken));
    }

    @Override
    @SuppressWarnings("unchecked")
    public AccessToken findAccessTokenByRefreshToken(String refreshToken, String clientId) {
        EntryObject eo = new PredicateBuilder().getEntryObject();
        Predicate<String, String> predicate = eo.get("refreshTokenByClient").equal(refreshToken + clientId + true);
        Collection<PersistentAccessToken> values = getAccessTokenContainer().values(predicate);
        // TODO: ensure only one active refresh token + client_id
        if (values.isEmpty()) {
            return null;
        }
        return PersistenceTransformations.toAccessToken(values.iterator().next());
    }

    @Override
    public void updateAccessTokenValidStatus(String accessToken, boolean valid) {
        PersistentAccessToken persistentAccessToken = getAccessTokenContainer().get(accessToken);
        persistentAccessToken.setValid(valid);
        getAccessTokenContainer().put(accessToken, persistentAccessToken);
    }

    @Override
    public AccessToken findAccessToken(String accessToken) {
        PersistentAccessToken tokenStored = getAccessTokenContainer().get(accessToken);
        if (tokenStored != null) {
            return PersistenceTransformations.toAccessToken(tokenStored);
        } else {
            return null;
        }
    }

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

    @Override
    public ClientCredentials findClientCredentials(String clientId) {
        return PersistenceTransformations.toClientCredentials(getClientCredentialsContainer().get(clientId));
    }

    @Override
    public boolean storeScope(Scope scope) {
        getScopesContainer().put(scope.getScope(), PersistenceTransformations.toPersistentScope(scope));
        return true;
    }

    @Override
    public List<Scope> getAllScopes() {
        List<Scope> scopesList = new ArrayList<Scope>();
        IMap<String, PersistentScope> scopesContainer = getScopesContainer();
        for (String key : scopesContainer.keySet()) {
            scopesList.add(PersistenceTransformations.toScope(scopesContainer.get(key)));
        }
        return scopesList;
    }

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

}
