/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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
package org.wso2.carbon.identity.authenticator.linkedIn;

import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.MockitoAnnotations.initMocks;

@RunWith(PowerMockRunner.class)
@PrepareForTest({LinkedInAuthenticator.class, OAuthAuthzResponse.class, OAuthClientRequest.class})
public class LinkedInAuthenticatorTest {

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Spy
    private AuthenticationContext context = new AuthenticationContext();

    @Mock
    private OAuthClientResponse oAuthClientResponse;

    @Mock
    private OAuthAuthzResponse mockOAuthAuthzResponse;

    @Mock
    private OAuthClient oAuthClient;

    @Mock
    private OAuthJSONAccessTokenResponse oAuthJSONAccessTokenResponse;

    private LinkedInAuthenticator linkedInAuthenticator;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @DataProvider(name = "authenticatorProperties")
    public Object[][] getAuthenticatorPropertiesData() {
        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, "test-client-id");
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, "test-client-secret");
        authenticatorProperties.put("callbackUrl", "http://localhost:9443/commonauth");
        return new Object[][] {{authenticatorProperties}};
    }

    @BeforeMethod
    public void setUp() {
        linkedInAuthenticator = new LinkedInAuthenticator();
        initMocks(this);
    }

    @Test(description = "Test case for canHandle method")
    public void testCanHandle() throws Exception {
        LinkedInAuthenticator spyAuthenticator = PowerMockito.spy(new LinkedInAuthenticator());
        Mockito.when(httpServletRequest.getParameter(Mockito.anyString())).thenReturn("dummy-code");
        Assert.assertTrue(linkedInAuthenticator.canHandle(httpServletRequest));
        PowerMockito.doReturn(true).when(spyAuthenticator, "getLoginType", httpServletRequest);
        Assert.assertTrue(spyAuthenticator.canHandle(httpServletRequest));
    }

    @Test(description = "Test case for handleErrorResponse method", expectedExceptions = InvalidCredentialsException.class)
    public void testHandleErrorResponse() throws Exception {
        Mockito.when(httpServletRequest.getParameter(LinkedInAuthenticatorConstants.OAUTH2_PARAM_ERROR))
                .thenReturn("error");
        Whitebox.invokeMethod(linkedInAuthenticator, "handleErrorResponse", httpServletRequest);
    }

    @Test(description = "Test case for getLoginType method")
    public void testGetLoginType() throws Exception {
        Mockito.when(httpServletRequest.getParameter(LinkedInAuthenticatorConstants.OAUTH2_PARAM_STATE)).thenReturn("");
        Assert.assertFalse((Boolean) Whitebox.invokeMethod(linkedInAuthenticator, "getLoginType", httpServletRequest));
        Mockito.when(httpServletRequest.getParameter(LinkedInAuthenticatorConstants.OAUTH2_PARAM_STATE))
                .thenReturn("linkedin");
        Assert.assertTrue((Boolean) Whitebox.invokeMethod(linkedInAuthenticator, "getLoginType", httpServletRequest));
    }

    @Test(description = "Test case for getAuthorizationServerEndpoint method", dataProvider = "authenticatorProperties")
    public void testGetAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) throws Exception {
        String authorizationServerEndpoint = linkedInAuthenticator
                .getAuthorizationServerEndpoint(authenticatorProperties);
        Assert.assertEquals(authorizationServerEndpoint, LinkedInAuthenticatorConstants.LINKEDIN_OAUTH_ENDPOINT);
    }

    @Test(description = "Test case for getTokenEndpoint method", dataProvider = "authenticatorProperties")
    public void testGetTokenEndpoint(Map<String, String> authenticatorProperties) {
        String tokenEndpoint = linkedInAuthenticator.getTokenEndpoint(authenticatorProperties);
        Assert.assertEquals(tokenEndpoint, LinkedInAuthenticatorConstants.LINKEDIN_TOKEN_ENDPOINT);
    }

    @Test(description = "Test case for getUserInfoEndpoint method", dataProvider = "authenticatorProperties")
    public void testGetUserInfoEndpoint(Map<String, String> authenticatorProperties) {
        String userInfoEndpoint = linkedInAuthenticator
                .getUserInfoEndpoint(oAuthClientResponse, authenticatorProperties);
        Assert.assertEquals(userInfoEndpoint, LinkedInAuthenticatorConstants.LINKEDIN_USERINFO_ENDPOINT);
    }

    @Test(description = "Test case for requiredIdToken method", dataProvider = "authenticatorProperties")
    public void testRequiredIdToken(Map<String, String> authenticatorProperties) {
        Assert.assertFalse(linkedInAuthenticator.requiredIDToken(authenticatorProperties));
    }

    @Test(description = "Test case for getFriendlyName method")
    public void testGetFriendlyName() {
        Assert.assertEquals(linkedInAuthenticator.getFriendlyName(),
                LinkedInAuthenticatorConstants.LINKEDIN_CONNECTOR_FRIENDLY_NAME);
    }

    @Test(description = "Test case for getName method")
    public void testGetName() {
        Assert.assertEquals(linkedInAuthenticator.getName(), LinkedInAuthenticatorConstants.LINKEDIN_CONNECTOR_NAME);
    }

    @Test(description = "Test case for initiateAuthenticationRequest method", dataProvider = "authenticatorProperties")
    public void testInitiateAuthenticationRequest(Map<String, String> authenticatorProperties) throws Exception {
        context.setAuthenticatorProperties(authenticatorProperties);
        PowerMockito.doNothing().when(httpServletResponse).sendRedirect(Mockito.anyString());
        linkedInAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
        Assert.assertTrue(context.isRequestAuthenticated());
    }

    @Test(description = "Test case for initiateAuthenticationRequest when authenticator properties null",
            expectedExceptions = AuthenticationFailedException.class)
    public void testInitiateAuthenticationRequestForNullAuthenticatorProperties() throws Exception {
        context.setAuthenticatorProperties(null);
        linkedInAuthenticator.initiateAuthenticationRequest(httpServletRequest, httpServletResponse, context);
    }

    @Test(description = "Test case for getCallbackUrl method", dataProvider = "authenticatorProperties")
    public void testGetCallbackUrl(Map<String, String> authenticatorProperties) {
        String callbackUrl = linkedInAuthenticator.getCallbackUrl(authenticatorProperties);
        Assert.assertEquals(callbackUrl, "http://localhost:9443/commonauth");
    }

    @Test(description = "Test case for processAuthenticationResponse method", dataProvider = "authenticatorProperties")
    public void testProcessAuthenticationResponse(Map<String, String> authenticatorProperties) throws Exception {
        LinkedInAuthenticator spyAuthenticator = PowerMockito.spy(new LinkedInAuthenticator());
        context.setAuthenticatorProperties(authenticatorProperties);
        PowerMockito.mockStatic(OAuthAuthzResponse.class);
        Mockito.when(OAuthAuthzResponse.oauthCodeAuthzResponse(Mockito.any(HttpServletRequest.class)))
                .thenReturn(mockOAuthAuthzResponse);
        PowerMockito.mockStatic(OAuthClientRequest.class);
        Mockito.when(OAuthClientRequest.tokenLocation(Mockito.anyString()))
                .thenReturn(new OAuthClientRequest.TokenRequestBuilder("/token"));
        PowerMockito.whenNew(OAuthClient.class).withAnyArguments().thenReturn(oAuthClient);
        Mockito.when(oAuthClient.accessToken(Mockito.any(OAuthClientRequest.class))).thenReturn(
                oAuthJSONAccessTokenResponse);
        Mockito.when(oAuthJSONAccessTokenResponse.getParam(LinkedInAuthenticatorConstants.ACCESS_TOKEN))
                .thenReturn("dummyToken");
        HashMap<ClaimMapping, String> claimMappings = new HashMap<>();
        ClaimMapping claimMapping = new ClaimMapping();
        Claim claim = new Claim();
        claim.setClaimUri("http://wso2.org/claims/sub");
        claimMapping.setLocalClaim(claim);
        claimMappings.put(new ClaimMapping(), "http://wso2.org/linkedin/claims/id");
        claimMappings.put(claimMapping, "testuser");
        Mockito.when(spyAuthenticator.getSubjectAttributes(oAuthJSONAccessTokenResponse, authenticatorProperties))
                .thenReturn(claimMappings);
        spyAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
        Assert.assertNotNull(context.getSubject());
        Assert.assertEquals(context.getSubject().getUserAttributes().size(), 2);
    }

    @Test(description = "Test case for processAuthenticationResponse method", dataProvider = "authenticatorProperties",
            expectedExceptions = AuthenticationFailedException.class)
    public void testProcessAuthenticationResponseForAccessTokenNull(Map<String, String> authenticatorProperties)
            throws Exception {
        context.setAuthenticatorProperties(authenticatorProperties);
        PowerMockito.mockStatic(OAuthAuthzResponse.class);
        Mockito.when(OAuthAuthzResponse.oauthCodeAuthzResponse(Mockito.any(HttpServletRequest.class)))
                .thenReturn(mockOAuthAuthzResponse);
        PowerMockito.mockStatic(OAuthClientRequest.class);
        Mockito.when(OAuthClientRequest.tokenLocation(Mockito.anyString()))
                .thenReturn(new OAuthClientRequest.TokenRequestBuilder("/token"));
        PowerMockito.whenNew(OAuthClient.class).withAnyArguments().thenReturn(oAuthClient);
        Mockito.when(oAuthClient.accessToken(Mockito.any(OAuthClientRequest.class))).thenReturn(
                oAuthJSONAccessTokenResponse);
        linkedInAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
    }

    @Test(description = "Test case for processAuthenticationResponse failed", dataProvider = "authenticatorProperties")
    public void testGetSubjectAttributes(Map<String, String> authenticatorProperties) throws Exception {
        LinkedInAuthenticator spyAuthenticator = PowerMockito.spy(new LinkedInAuthenticator());
        Mockito.when(oAuthClientResponse.getParam("access_token")).thenReturn("dummytoken");
        PowerMockito.doReturn("{\"id\":\"testuser\"}")
                .when(spyAuthenticator, "sendRequest", Mockito.anyString(), Mockito.anyString());
        Map<ClaimMapping, String> claimMappings = spyAuthenticator
                .getSubjectAttributes(oAuthClientResponse, authenticatorProperties);
        Assert.assertEquals(1, claimMappings.size());
        for (ClaimMapping claimMapping : claimMappings.keySet()) {
            Assert.assertEquals("http://wso2.org/linkedin/claims/id", claimMapping.getLocalClaim().getClaimUri());
            Assert.assertEquals("testuser", claimMappings.get(claimMapping));
        }
    }
}
