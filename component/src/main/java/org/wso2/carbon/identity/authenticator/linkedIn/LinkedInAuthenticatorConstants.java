/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.linkedIn;

public class LinkedInAuthenticatorConstants {
    public static final String LINKEDIN_OAUTH_ENDPOINT = "https://www.linkedin.com/uas/oauth2/authorization";
    public static final String LINKEDIN_TOKEN_ENDPOINT = "https://www.linkedin.com/uas/oauth2/accessToken";
    public static final String LINKEDIN_USERINFO_ENDPOINT = "https://api.linkedin.com/v1/people/~:(id,first-name,last-name,industry,headline,email-address)?format=json";
    public static final String LINKEDIN_CONNECTOR_FRIENDLY_NAME = "linkedIn ";
    public static final String LINKEDIN_CONNECTOR_NAME = "LinkedInOauth2OpenIDAuthenticator";
    public static final String QUERY_STRING = "scope=r_basicprofile%20r_emailaddress";
    public static final String LINKEDIN_OAUTH2_ACCESS_TOKEN_PARAMETER = "oauth2_access_token";
    public static final String LINKEDIN_LOGIN_TYPE = "linkedin";
    public static final String OAUTH2_GRANT_TYPE_CODE = "code";
    public static final String OAUTH2_PARAM_STATE = "state";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String CLIENT_ID = "Client Id";
    public static final String CLIENT_SECRET = "Client Secret";
    public static final String OAUTH2_AUTHZ_URL = "OAuth2AuthzUrl";
    public static final String OAUTH2_TOKEN_URL = "OAUTH2TokenUrl";
    public static final String CALLBACK_URL = "https://localhost:9443/commonauth";
    public static final String DOMAIN = "domain";
}