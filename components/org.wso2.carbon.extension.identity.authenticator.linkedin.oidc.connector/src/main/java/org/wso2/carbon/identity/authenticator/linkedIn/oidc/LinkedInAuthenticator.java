/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.authenticator.linkedIn.oidc;

import org.apache.commons.lang.StringUtils;
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
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Authenticator of linkedIn OIDC.
 * API version: V2.0
 * API Document: https://learn.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin-v2
 */
public class LinkedInAuthenticator extends OpenIDConnectAuthenticator {

    private static final Log log = LogFactory.getLog(LinkedInAuthenticator.class);

    /**
     * check whether user can process or not.
     *
     * @param request the request
     * @return true or false
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {

        String grantType = request.getParameter(LinkedInAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE);
        String stateParam = request.getParameter(LinkedInAuthenticatorConstants.OAUTH2_PARAM_STATE);
        String errorParam = request.getParameter(LinkedInAuthenticatorConstants.OAUTH2_PARAM_ERROR);
        boolean loginTypePresent = isLoginTypeLinkedIn(request);

        if (log.isDebugEnabled()) {
            log.debug("Inside LinkedinOIDCAuthenticator.canHandle()");
            log.debug("Parameter values: ");
            log.debug("Is login type Linkedin: " + loginTypePresent);
            log.debug(LinkedInAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE + ":" + grantType);
            log.debug(LinkedInAuthenticatorConstants.OAUTH2_PARAM_STATE + ":" + stateParam);
            log.debug(LinkedInAuthenticatorConstants.OAUTH2_PARAM_ERROR + ":" + errorParam);
        }

        return StringUtils.isNotEmpty(grantType) && stateParam != null && loginTypePresent || errorParam != null;
    }

    /**
     * Handle error response when click on cancel without providing credentials.
     *
     * @param request httpServletRequest
     * @throws InvalidCredentialsException
     */
    private void handleErrorResponse(HttpServletRequest request) throws InvalidCredentialsException {

        if (request.getParameter(LinkedInAuthenticatorConstants.OAUTH2_PARAM_ERROR) != null) {
            StringBuilder errorMessage = new StringBuilder();
            String error = request.getParameter(LinkedInAuthenticatorConstants.OAUTH2_PARAM_ERROR);
            String errorDescription = request
                    .getParameter(LinkedInAuthenticatorConstants.OAUTH2_PARAM_ERROR_DESCRIPTION);
            String state = request.getParameter(LinkedInAuthenticatorConstants.OAUTH2_PARAM_STATE);
            errorMessage.append(LinkedInAuthenticatorConstants.ERROR)
                    .append(error)
                    .append(LinkedInAuthenticatorConstants.ERROR_DESCRIPTION).append(errorDescription)
                    .append(LinkedInAuthenticatorConstants.STATE)
                    .append(state);
            if (log.isDebugEnabled()) {
                log.debug("Failed to authenticate via LinkedIn OIDC when click on cancel without providing credentials. "
                        + errorMessage.toString());
            }
            throw new InvalidCredentialsException(errorMessage.toString());
        }
    }

    /**
     * check whether the state contain login type or not.
     *
     * @param request the request
     * @return login type
     */
    private Boolean isLoginTypeLinkedIn(HttpServletRequest request) {

        String state = request.getParameter(LinkedInAuthenticatorConstants.OAUTH2_PARAM_STATE);
        if (StringUtils.isNotEmpty(state)) {
            return state.contains(LinkedInAuthenticatorConstants.LINKEDIN_LOGIN_TYPE);
        } else {
            return false;
        }
    }

    /**
     * Get linkedIn authorization endpoint.
     */
    @Override
    protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {

        String authorizationEP;
        if (authenticatorProperties != null) {
            authorizationEP = authenticatorProperties.get(LinkedInAuthenticatorConstants.OAUTH2_AUTHZ_URL);
        } else {
            authorizationEP = LinkedInAuthenticatorConstants.LINKEDIN_V2_OAUTH_ENDPOINT;
        }

        return StringUtils.isNotEmpty(authorizationEP) ? authorizationEP : LinkedInAuthenticatorConstants
                .LINKEDIN_V2_OAUTH_ENDPOINT;
    }

    /**
     * Get linkedIn token endpoint.
     */
    @Override
    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {

        String tokenEndPoint;
        if (authenticatorProperties != null) {
            tokenEndPoint = authenticatorProperties.get(LinkedInAuthenticatorConstants.OAUTH2_TOKEN_URL);
        } else {
            tokenEndPoint = LinkedInAuthenticatorConstants.LINKEDIN_V2_TOKEN_ENDPOINT;
        }

        return StringUtils.isNotEmpty(tokenEndPoint) ? tokenEndPoint : LinkedInAuthenticatorConstants
                .LINKEDIN_V2_TOKEN_ENDPOINT;
    }

    /**
     * Get linkedIn user info endpoint.
     */
    @Override
    protected String getUserInfoEndpoint(OAuthClientResponse token, Map<String, String> authenticatorProperties) {

        String userinfoEndpoint;
        if (authenticatorProperties != null) {
            userinfoEndpoint = authenticatorProperties.get(LinkedInAuthenticatorConstants.USERINFO_ENDPOINT);
        } else {
            userinfoEndpoint = LinkedInAuthenticatorConstants.LINKEDIN_V2_USERINFO_ENDPOINT;
        }

        return StringUtils.isNotEmpty(userinfoEndpoint) ? userinfoEndpoint : LinkedInAuthenticatorConstants
                .LINKEDIN_V2_USERINFO_ENDPOINT;
    }

    /**
     * Check ID token in linkedIn OAuth.
     */
    @Override
    protected boolean requiredIDToken(Map<String, String> authenticatorProperties) {
        return false;
    }

    /**
     * Get the friendly name of the Authenticator.
     */
    @Override
    public String getFriendlyName() {
        return LinkedInAuthenticatorConstants.LINKEDIN_OIDC_CONNECTOR_FRIENDLY_NAME;
    }

    /**
     * Get the name of the Authenticator.
     */
    @Override
    public String getName() {
        return LinkedInAuthenticatorConstants.LINKEDIN_OIDC_CONNECTOR_NAME;
    }


    /**
     * Get Configuration Properties.
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        Property clientId = new Property();
        clientId.setName(OIDCAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName(LinkedInAuthenticatorConstants.CLIENT_ID);
        clientId.setRequired(true);
        clientId.setDescription("Enter Linkedin IDP client identifier value");
        clientId.setDisplayOrder(0);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(OIDCAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName(LinkedInAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter Linkedin IDP client secret value");
        clientSecret.setDisplayOrder(1);
        configProperties.add(clientSecret);

        Property callbackUrl = new Property();
        callbackUrl.setDisplayName("Callback URL");
        callbackUrl.setName(LinkedInAuthenticatorConstants.CALLBACK_URL);
        callbackUrl.setDescription("Enter value corresponding to callback url.");
        callbackUrl.setRequired(true);
        callbackUrl.setDisplayOrder(2);
        configProperties.add(callbackUrl);

        return configProperties;
    }

    /**
     * This is override because of query string values hard coded and input
     * values validations are not required.
     *
     * @param request  the http request
     * @param response the http response
     * @param context  the authentication context
     * @throws AuthenticationFailedException
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            if (authenticatorProperties != null) {
                String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
                String authorizationEP = getAuthorizationServerEndpoint(authenticatorProperties);
                String callBackUrl = getCallbackUrl(authenticatorProperties);
                String state = context.getContextIdentifier() + "," + LinkedInAuthenticatorConstants
                        .LINKEDIN_LOGIN_TYPE;
                state = getState(state, authenticatorProperties);
                OAuthClientRequest authzRequest = OAuthClientRequest
                        .authorizationLocation(authorizationEP)
                        .setClientId(clientId)
                        .setRedirectURI(callBackUrl)
                        .setResponseType(LinkedInAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)
                        .setState(state)
                        .setScope(LinkedInAuthenticatorConstants.SCOPE)
                        .buildQueryMessage();
                String loginPage = authzRequest.getLocationUri();
                response.sendRedirect(loginPage);
            } else {
                throw new AuthenticationFailedException("Authenticator Properties cannot be null.");
            }
        } catch (IOException | OAuthSystemException e) {
            throw new AuthenticationFailedException("Error while initiating authentication request.", e);
        }
    }

    /**
     * Get the CallBackURL.
     */
    @Override
    protected String getCallbackUrl(Map<String, String> authenticatorProperties) {
        return authenticatorProperties.get(LinkedInAuthenticatorConstants.CALLBACK_URL);
    }

    /**
     * This method are overridden for extra claim request to LinkedIn end-point.
     *
     * @param request  the http request
     * @param response the http response
     * @param context  the authentication context
     * @throws AuthenticationFailedException
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            // Authentication response can be an error response. So we need to handle it first.
            handleErrorResponse(request);

            // Get the authorization code from the response.
            OAuthAuthzResponse authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            String code = authzResponse.getCode();

            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID);
            String clientSecret = authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_SECRET);
            String tokenEndPoint = getTokenEndpoint(authenticatorProperties);
            String callbackUrl = getCallbackUrl(authenticatorProperties);

            OAuthClientRequest accessRequest;
            try {
                accessRequest = OAuthClientRequest.tokenLocation(tokenEndPoint)
                        .setGrantType(GrantType.AUTHORIZATION_CODE)
                        .setClientId(clientId)
                        .setClientSecret(clientSecret)
                        .setRedirectURI(callbackUrl)
                        .setCode(code)
                        .buildBodyMessage();

                // Create OAuth client that uses custom http client under the hood.
                OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());

                // Request access token.
                OAuthClientResponse oAuthResponse = oAuthClient.accessToken(accessRequest);
                String accessToken = oAuthResponse.getParam(LinkedInAuthenticatorConstants.ACCESS_TOKEN);

                if (StringUtils.isEmpty(accessToken)) {
                    throw new AuthenticationFailedException("Authentication Failed. Didn't receive the access token.");
                }

                // Call the user info endpoint and get the user claims.
                Map<ClaimMapping, String> claims = getSubjectAttributes(oAuthResponse, authenticatorProperties);
                if (claims == null || claims.isEmpty()) {
                    throw new AuthenticationFailedException("Selected user profile not found.");
                }

                // Set email as the authenticated subject identifier and create a federated user.
                ClaimMapping emailClaimMapping = ClaimMapping.build(LinkedInAuthenticatorConstants.EMAIL_ADDRESS_CLAIM,
                        LinkedInAuthenticatorConstants.EMAIL_ADDRESS_CLAIM, null, false);
                AuthenticatedUser authenticatedUser = AuthenticatedUser
                        .createFederateAuthenticatedUserFromSubjectIdentifier(claims.get(emailClaimMapping));
                authenticatedUser.setUserAttributes(claims);

                // Set the above user as the subject and conclude the flow.
                context.setSubject(authenticatedUser);
            } catch (OAuthSystemException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Exception while building request for request access token", e);
                }
                throw new AuthenticationFailedException(e.getMessage(), e);
            }
        } catch (OAuthProblemException e) {
            throw new AuthenticationFailedException("Authentication Failed in oauthresponse ", e);
        }
    }

    /**
     * Extra request sending to LinkedIn userinfo end-point.
     *
     * @param url         the request url
     * @param accessToken the accesstoken
     * @throws IOException
     */
    protected String sendRequest(String url, String accessToken) throws IOException {

        if (log.isDebugEnabled()) {
            log.debug("claim url: " + url);
        }

        URL obj = new URL(url);
        HttpURLConnection urlConnection = (HttpURLConnection) obj.openConnection();
        urlConnection.setRequestMethod("GET");
        urlConnection.setRequestProperty("Authorization", "Bearer " + accessToken);

        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
        StringBuilder stringBuilder = new StringBuilder();
        String inputLine = bufferedReader.readLine();
        while (inputLine != null) {
            stringBuilder.append(inputLine).append("\n");
            inputLine = bufferedReader.readLine();
        }
        bufferedReader.close();
        if (log.isDebugEnabled()) {
            log.debug("response: " + stringBuilder.toString());
        }
        return stringBuilder.toString();
    }

    /**
     * Get the Linkedin specific claim dialect URI.
     * @return Claim dialect URI.
     */
    @Override
    public String getClaimDialectURI() {

        return LinkedInAuthenticatorConstants.CLAIM_DIALECT_URI;
    }

    @Override
    protected Map<ClaimMapping, String> getSubjectAttributes(OAuthClientResponse token, Map<String,
            String> authenticatorProperties) {

        HashMap<ClaimMapping, String> claims = new HashMap<>();

        if (token == null) {
            return claims;
        }
        try {
            String accessToken = token.getParam(LinkedInAuthenticatorConstants.ACCESS_TOKEN);

            String userInfoEndpoint = this.getUserInfoEndpoint(token, authenticatorProperties);
            String json = this.sendRequest(userInfoEndpoint, accessToken);
            if (StringUtils.isBlank(json)) {
                if (log.isDebugEnabled()) {
                    log.debug("Empty JSON response from user info endpoint. Unable to fetch user claims." +
                            " Proceeding without user claims");
                }
                return claims;
            }

            Map<String, Object> jsonObject = JSONUtils.parseJSON(json);
            for (Map.Entry<String, Object> entry : jsonObject.entrySet()) {
                String key = entry.getKey();
                claims.put(ClaimMapping.build(LinkedInAuthenticatorConstants.CLAIM_DIALECT_URI + "/" + key,
                        LinkedInAuthenticatorConstants.CLAIM_DIALECT_URI + "/" + key, null, false),
                        jsonObject.get(key).toString());

                if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable("UserClaims")) {
                    log.debug("Adding claims from end-point data mapping : " + key + " - " + jsonObject.get(key)
                            .toString());
                }
            }
        } catch (Exception e) {
            log.error("Error occurred while accessing user info endpoint", e);
        }
        return claims;
    }
}
