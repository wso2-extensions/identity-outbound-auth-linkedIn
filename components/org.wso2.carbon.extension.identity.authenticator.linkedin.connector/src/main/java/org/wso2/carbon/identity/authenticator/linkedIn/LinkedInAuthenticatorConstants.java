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

    @Deprecated
    public static final String LINKEDIN_OAUTH_ENDPOINT = "https://www.linkedin.com/uas/oauth2/authorization";
    public static final String LINKEDIN_OAUTH_ENDPOINT_V2 = "https://www.linkedin.com/oauth/v2/authorization";

    @Deprecated
    public static final String LINKEDIN_TOKEN_ENDPOINT = "https://www.linkedin.com/uas/oauth2/accessToken";
    public static final String LINKEDIN_TOKEN_ENDPOINT_V2 = "https://www.linkedin.com/oauth/v2/accessToken";

    @Deprecated
    public static final String LINKEDIN_USERINFO_ENDPOINT = "https://api.linkedin.com/v1/people/~:(id,first-name,last-name,industry,headline,email-address)?format=json";
    public static final String LINKEDIN_USERINFO_ENDPOINT_V2 = "https://api.linkedin.com/v2/userinfo";

    public static final String LINKEDIN_EMAIL_ENDPOINT = "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))";

    public static final String LINKEDIN_CONNECTOR_FRIENDLY_NAME = "LinkedInSOOOO";
    public static final String LINKEDIN_CONNECTOR_NAME = "LinkedInSOS";

    @Deprecated
    public static final String QUERY_STRING = "scope=r_basicprofile%20r_emailaddress";
    public static final String SCOPE = "r_liteprofile r_emailaddress";
    public static final String LINKEDIN_LOGIN_TYPE = "linkedin";
    public static final String OAUTH2_GRANT_TYPE_CODE = "code";
    public static final String OAUTH2_PARAM_STATE = "state";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String CLIENT_ID = "Client Id";
    public static final String CLIENT_SECRET = "Client Secret";
    public static final String OAUTH2_AUTHZ_URL = "OAuth2AuthzUrl";
    public static final String OAUTH2_TOKEN_URL = "OAUTH2TokenUrl";
    public static final String CALLBACK_URL = "callbackUrl";
    public static final String CLAIM_DIALECT_URI = "http://wso2.org/linkedin/claims";
    public static final String OAUTH2_PARAM_ERROR = "error";
    public static final String OAUTH2_PARAM_ERROR_DESCRIPTION = "error_description";
    public static final String ERROR = "error: ";
    public static final String ERROR_DESCRIPTION = ", error_description: ";
    public static final String STATE = ", state: ";
    public static final String USERINFO_ENDPOINT = "userinfo_endpoint";
    public static final String EMAIL_ENDPOINT = "email_endpoint";
    public static final String EMAIL_ADDRESS_CLAIM = "http://wso2.org/linkedin/claims/emailAddress";
    public static final String ELEMENTS_ATTRIBUTE = "elements";
    public static final String HANDLE_ATTRIBUTE = "handle~";
    public static final String EMAIL_ADDRESS_ATTRIBUTE = "emailAddress";
}
