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

package org.wso2.carbon.identity.authenticator.LinkedIn;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Authenticator of LinkedIn
 */
public class LinkedInAuthenticator extends OpenIDConnectAuthenticator implements FederatedApplicationAuthenticator {

    private static Log log = LogFactory.getLog(LinkedInAuthenticator.class);

    @Override
    public boolean canHandle(HttpServletRequest request) {
        if (log.isTraceEnabled()) {
            log.trace("Inside LinkedinOAuth2Authenticator.canHandle()");
        }
        // Check commonauth got an OIDC response
        if (request.getParameter(LinkedInAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE) != null
                && request.getParameter(LinkedInAuthenticatorConstants.OAUTH2_PARAM_STATE) != null
                && LinkedInAuthenticatorConstants.LINKEDIN_LOGIN_TYPE.equals(getLoginType(request))) {
            return true;
        }
        return false;
    }

    private String getLoginType(HttpServletRequest request) {
        String state = request.getParameter(LinkedInAuthenticatorConstants.OAUTH2_PARAM_STATE);
        if (state != null) {
            return state.split(",")[1];
        } else {
            return null;
        }
    }

    /**
     * Get LinkedIn authorization endpoint.
     */
    @Override
    protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {
        return LinkedInAuthenticatorConstants.LINKEDIN_OAUTH_ENDPOINT;
    }

    /**
     * Get LinkedIn token endpoint.
     */
    @Override
    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {
        return LinkedInAuthenticatorConstants.LINKEDIN_TOKEN_ENDPOINT;
    }

    /**
     * Get LinkedIn user info endpoint.
     */
    @Override
    protected String getUserInfoEndpoint(OAuthClientResponse token, Map<String, String> authenticatorProperties) {
        return LinkedInAuthenticatorConstants.LINKEDIN_USERINFO_ENDPOINT;
    }

    /**
     * Check ID token in LinkedIn OAuth.
     */
    @Override
    protected boolean requiredIDToken(Map<String, String> authenticatorProperties) {
        return false;
    }

    /**
     * Get the friendly name of the Authenticator
     */
    @Override
    public String getFriendlyName() {
        return LinkedInAuthenticatorConstants.LINKEDIN_CONNECTOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator
     */
    @Override
    public String getName() {
        return LinkedInAuthenticatorConstants.LINKEDIN_CONNECTOR_NAME;
    }

    /**
     * Get Configuration Properties
     */
    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<Property>();

        Property clientId = new Property();
        clientId.setName(LinkedInAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter Linkedin IDP client identifier value");
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(LinkedInAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter Linkedin IDP client secret value");
        configProperties.add(clientSecret);

        return configProperties;
    }


    /**
     * This is override because of query string values hard coded and input
     * values validations are not required.
     *
     * @param request
     * @param response
     * @param context
     * @throws AuthenticationFailedException
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {
        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            if (authenticatorProperties != null) {
                String clientId = authenticatorProperties.get(LinkedInAuthenticatorConstants.CLIENT_ID);
                String authorizationEP = getAuthorizationServerEndpoint(authenticatorProperties);
                if (authorizationEP == null) {
                    authorizationEP = authenticatorProperties
                            .get(LinkedInAuthenticatorConstants.OAUTH2_AUTHZ_URL);
                }
                String callbackurl = getCallbackUrl(authenticatorProperties);
                String state = context.getContextIdentifier() + ","
                        + LinkedInAuthenticatorConstants.LINKEDIN_LOGIN_TYPE;
                state = getState(state, authenticatorProperties);
                OAuthClientRequest authzRequest;
                // This is the query string need to send getting email and
                // profile
                String queryString = LinkedInAuthenticatorConstants.QUERY_STRING;
                authzRequest = OAuthClientRequest
                        .authorizationLocation(authorizationEP)
                        .setClientId(clientId)
                        .setRedirectURI(callbackurl)
                        .setResponseType(LinkedInAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)
                        .setState(state).buildQueryMessage();
                String loginPage = authzRequest.getLocationUri();
                String domain = request.getParameter("domain");
                if (domain != null) {
                    loginPage = loginPage + "&fidp=" + domain;
                }
                if (queryString != null) {
                    if (!queryString.startsWith("&")) {
                        loginPage = loginPage + "&" + queryString;
                    } else {
                        loginPage = loginPage + queryString;
                    }
                }
                response.sendRedirect(loginPage);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Error while retrieving properties. Authenticator Properties cannot be null");
                }
                throw new AuthenticationFailedException(
                        "Error while retrieving properties. Authenticator Properties cannot be null");
            }
        } catch (IOException e) {
            log.error("Exception while sending to the login page", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (OAuthSystemException e) {
            log.error("Exception while building authorization code request", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
        return;
    }

    /**
     * @return
     */
    @Override
    protected String getCallbackUrl(Map<String, String> authenticatorProperties) {
        return LinkedInAuthenticatorConstants.CALLBACK_URL;
    }

    /**
     * this method are overridden for extra claim request to linkedin end-point
     *
     * @param request
     * @param response
     * @param context
     * @throws AuthenticationFailedException
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {
        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = authenticatorProperties.get(LinkedInAuthenticatorConstants.CLIENT_ID);
            String clientSecret = authenticatorProperties.get(LinkedInAuthenticatorConstants.CLIENT_SECRET);
            String tokenEndPoint = getTokenEndpoint(authenticatorProperties);
            if (tokenEndPoint == null) {
                tokenEndPoint = authenticatorProperties.get(LinkedInAuthenticatorConstants.OAUTH2_TOKEN_URL);
            }
            String callbackurl = getCallbackUrl(authenticatorProperties);
            OAuthAuthzResponse authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            String code = authzResponse.getCode();
            OAuthClientRequest accessRequest;
            try {
                accessRequest = OAuthClientRequest.tokenLocation(tokenEndPoint)
                        .setGrantType(GrantType.AUTHORIZATION_CODE)
                        .setClientId(clientId).setClientSecret(clientSecret)
                        .setRedirectURI(callbackurl).setCode(code)
                        .buildBodyMessage();
            } catch (OAuthSystemException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Exception while building request for request access token", e);
                }
                throw new AuthenticationFailedException(e.getMessage(), e);
            }
            // create OAuth client that uses custom http client under the hood
            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
            OAuthClientResponse oAuthResponse = null;
            try {
                oAuthResponse = oAuthClient.accessToken(accessRequest);
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    log.debug("Exception while requesting access token", e);
                }
                throw new AuthenticationFailedException(e.getMessage(), e);
            }
            AuthenticatedUser authenticatedUserObj;
            String accessToken = oAuthResponse.getParam(LinkedInAuthenticatorConstants.ACCESS_TOKEN);
            if (accessToken != null) {
                Map<ClaimMapping, String> claims;
                Map<String, Object> userClaims = getUserClaims(oAuthResponse);
                if (userClaims != null && !userClaims.isEmpty()) {
                    authenticatedUserObj = AuthenticatedUser
                            .createFederateAuthenticatedUserFromSubjectIdentifier(String.valueOf(userClaims.get("id")));
                    authenticatedUserObj
                            .setAuthenticatedSubjectIdentifier(String.valueOf(userClaims.get("lastName")));
                    claims = getSubjectAttributes(oAuthResponse, authenticatorProperties);
                    authenticatedUserObj.setUserAttributes(claims);
                    context.setSubject(authenticatedUserObj);
                } else {
                    throw new AuthenticationFailedException("Selected user profile found");
                }
            } else {
                throw new AuthenticationFailedException("Authentication Failed");
            }
        } catch (OAuthProblemException e) {
            log.error(e.getMessage(), e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    /**
     * extra request sending to linkedin userinfo end-point
     *
     * @param url
     * @param accessToken
     * @return
     * @throws IOException
     */
    protected String sendRequest(String url, String accessToken)
            throws IOException {
        if (log.isDebugEnabled()) {
            log.debug("claim url: " + url + " <> accessToken : " + accessToken);
        }
        URL obj = new URL(url + "&" + LinkedInAuthenticatorConstants
                .LINKEDIN_OAUTH2_ACCESS_TOKEN_PARAMETER + "=" + accessToken);
        HttpURLConnection urlConnection = (HttpURLConnection) obj.openConnection();
        urlConnection.setRequestMethod("GET");
        BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
        StringBuilder b = new StringBuilder();
        String inputLine = in.readLine();
        while (inputLine != null) {
            b.append(inputLine).append("\n");
            inputLine = in.readLine();
        }
        in.close();
        if (log.isDebugEnabled()) {
            log.debug("response: " + b.toString());
        }
        return b.toString();
    }

    protected Map<String, Object> getUserClaims(OAuthClientResponse token) {
        try {
            String json = sendRequest(
                    LinkedInAuthenticatorConstants.LINKEDIN_USERINFO_ENDPOINT,
                    token.getParam(LinkedInAuthenticatorConstants.ACCESS_TOKEN));
            Map<String, Object> jsonObject = JSONUtils.parseJSON(json);
            return jsonObject;
        } catch (Exception e) {
            log.error(e);
        }
        return new HashMap<String, Object>();
    }

}

