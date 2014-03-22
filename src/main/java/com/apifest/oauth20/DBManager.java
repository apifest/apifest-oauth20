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

/**
 * @author Apostol Terziev
 */
package com.apifest.oauth20;

import java.util.List;

public interface DBManager {
    boolean validClient(String clientId, String clientSecret);
    void storeClientCredentials(ClientCredentials clientCreds);
    void storeAuthCode(AuthCode authCode);
    void updateAuthCodeValidStatus(String authCode, boolean valid);
    void storeAccessToken(AccessToken accessToken);
    AccessToken findAccessTokenByRefreshToken(String refreshToken, String clientId);
    void updateAccessTokenValidStatus(String accessToken, boolean valid);
    AccessToken findAccessToken(String accessToken);
    AuthCode findAuthCode(String authCode, String redirectUri);
    ClientCredentials findClientCredentials(String clientId);

    boolean storeScope(Scope scope);
    List<Scope> getAllScopes();
}
