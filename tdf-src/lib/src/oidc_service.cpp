//
// Created by Sujan Reddy on 7/16/21.
//

#include <iostream>
#include <future>
#include "nlohmann/json.hpp"
#include <utility>

#include <jwt-cpp/jwt.h>
#include "network/http_service_provider.h"
#include "tdf_exception.h"
#include "utils.h"
#include "sdk_constants.h"
#include "crypto/crypto_utils.h"
#include "oidc_service.h"


namespace virtru {

    using namespace virtru::network;

    // TODO: Should be moved to some common header file.
    static constexpr auto kBearerToken = "Bearer";
    static constexpr auto kClientCredentials = "client_credentials";
    static constexpr auto kPasswordCredentials = "password";
    static constexpr auto kClientID = "client_id";
    static constexpr auto kClientSecret = "client_secret";
    static constexpr auto kUsername = "username";
    static constexpr auto kPassword = "password";
    static constexpr auto kRefreshToken = "refresh_token";
    static constexpr auto kAccessToken = "access_token";
    static constexpr auto kGrantType = "grant_type";
    static constexpr auto kKCRealmPath = "/auth/realms/";
    static constexpr auto kOIDCTokenPath = "/protocol/openid-connect/token";
    static constexpr auto kOIDCUserinfoPath = "/protocol/openid-connect/userinfo";
    static constexpr auto kKeycloakPubkeyHeader = "X-VirtruPubKey";
    static constexpr auto kContentTypeUrlFormEncode = "application/x-www-form-urlencoded";

    using namespace virtru::crypto;

    /// Constructor
    OIDCService::OIDCService(OIDCCredentials  oidcCredentials,
                             const HttpHeaders& headers,
                             const std::string& clientSigningPubkey)
                             : m_oidcCredentials(std::move(oidcCredentials)) {
        m_clientSigningPubkey = base64UrlEncode(clientSigningPubkey);
        m_networkServiceProvider = std::make_unique<HTTPServiceProvider>(headers);
    }

    /// Create the header key/value pairs that should be added to the request to establish authorization
    std::map<std::string, std::string> OIDCService::generateAuthHeaders() {

        LogTrace("OIDCService::generateAuthHeaders");

        std::ostringstream authHeaderStream;
        std::map<std::string, std::string> authHeader;

        if(m_oidcCredentials.getAuthType() == OIDCCredentials::AuthType::None){
            ThrowException("OIDC credentials are missing");
        }

        // If the credentials object already have an access token, use it.
        if (m_oidcCredentials.getAuthType() == OIDCCredentials::AuthType::Client ||
            m_oidcCredentials.getAuthType() == OIDCCredentials::AuthType::User) {
            getAccessToken();
            authHeaderStream << kBearerToken << " " << m_accessToken;

            authHeader.insert({kAuthorizationKey, authHeaderStream.str()});
        } else if (m_oidcCredentials.getAuthType() == OIDCCredentials::AuthType::AccessToken) {
            authHeaderStream << kBearerToken << " " << m_oidcCredentials.getAccessToken();
            authHeader.insert({kAuthorizationKey, authHeaderStream.str()});
        } else {
            ThrowException("Auth type not supported");
        }

        auto decoded_token = jwt::decode(m_accessToken);
        nlohmann::json tokenAsJson = nlohmann::json::parse(decoded_token.get_payload());
        m_preferredUsername = tokenAsJson[kPreferredUsername];

        LogDebug("Preffered username: " +  m_preferredUsername);
        LogDebug("Authorization = " + authHeaderStream.str());
        return authHeader;
    }

    // Return the attributes that are in claims object(part of access token)
    std::vector<std::string> OIDCService::getClaimsObjectAttributes() {
        if (m_accessToken.empty()) {
            ThrowException("Access token missing from OIDC service");
        }

        auto decoded_token = jwt::decode(m_accessToken);
        nlohmann::json tokenAsJson = nlohmann::json::parse(decoded_token.get_payload());
        nlohmann::json subjectAttributes = nlohmann::json::array();
        subjectAttributes = tokenAsJson[kTDFClaims][kSubjectAttributes];

        std::vector<std::string> attributes;
        attributes.reserve(subjectAttributes.size());
        for (const auto &subjectAttribute: subjectAttributes) {
            std::string attribute = subjectAttribute[kAttribute];
            attributes.push_back(attribute);
        }

        return attributes;
    }

    /// Get the access token from the OIDC server.
    /// If our AccessToken is expired on userInfo call - then
    /// trigger a refresh using the refresh token.
    /// If THAT fails, then bail
    void OIDCService::getAccessToken() {

        if (m_accessToken.empty()) {
            //We don't have cached tokens, fetch
            fetchAccessToken();
        } else {
            //First, try to grab the cached accessToken
            //and hit up the userinfo endpoint with it
            try {
                checkAccessToken();
                //That worked? Cool, token is still valid, return
                LogDebug("Access token valid");
            } catch (const Exception &exception) {
                LogWarn("UserInfo request failed, attempting refresh");
                try {

                    // Get a new access token using the refresh token
                    if (!m_refreshToken.empty()) {
                        refreshAccessToken();
                    } else {
                        fetchAccessToken();
                    }
                } catch (const Exception &refreshException) {
                    LogWarn("Refresh token rejected, attempting to regenerate tokens with credentials");
                    //Last-ditch effort, maybe our client creds are still valid even if
                    //our refresh and access tokens aren't - try to fetch a new tokenset from scratch
                    fetchAccessToken();
                }
            }
        }
    }

    /// Exchange the credentials with OIDC server and fetch the access token
    void OIDCService::fetchAccessToken() {

        LogTrace("OIDCService::fetchAccessToken");
        unsigned status = kHTTPBadRequest;
        std::promise<void> netPromise;
        auto netFuture = netPromise.get_future();
        std::string responseJson;
        std::ostringstream tokenBody;

        std::string oidcIdP = m_oidcCredentials.getOIDCEndpoint() +
                              kKCRealmPath + m_oidcCredentials.getOrgName() + kOIDCTokenPath;

        if (m_oidcCredentials.getAuthType() == OIDCCredentials::AuthType::Client) {
            addFormData(tokenBody, kGrantType, kClientCredentials);
            addFormData(tokenBody, kClientID, m_oidcCredentials.getClientId());
            addFormData(tokenBody, kClientSecret, m_oidcCredentials.getClientSecret());
        } else { // assume password
            addFormData(tokenBody, kUsername, m_oidcCredentials.getUsername());
            addFormData(tokenBody, kPassword, m_oidcCredentials.getPassword());
            addFormData(tokenBody, kGrantType, kPasswordCredentials);
            addFormData(tokenBody, kClientID, m_oidcCredentials.getClientId());
        }

        LogDebug("OIDCService::fetchAccessToken: Sending POST request: " + tokenBody.str());

        m_networkServiceProvider->executePost(
                oidcIdP, {{kContentTypeKey,       kContentTypeUrlFormEncode},
                          {kKeycloakPubkeyHeader, m_clientSigningPubkey}},
                tokenBody.str(),
                [&netPromise, &responseJson, &status](unsigned int statusCode, std::string &&response) {
                    status = statusCode;
                    responseJson = response;
                    netPromise.set_value();
                });

        // Wait here for a response
        netFuture.get();

        // Handle HTTP error.
        if (!Utils::goodHttpStatus(status)) {
            std::string exceptionMsg = "Get OIDC token failed status: ";
            exceptionMsg += std::to_string(status);
            exceptionMsg += responseJson;
            ThrowException(std::move(exceptionMsg));
        }

        LogDebug("Got OIDC fetchAccessToken response: " + responseJson);
        nlohmann::json tokens = nlohmann::json::parse(responseJson);
        if (!tokens.contains(kAccessToken)) {
            std::string exceptionMsg = "OIDC access token not found in /openid-connect/token response";
            ThrowException(std::move(exceptionMsg));
        }

        m_accessToken = tokens[kAccessToken];

        //credential exchange does not always return a refresh token,
        if (tokens.contains(kRefreshToken)) {
            m_refreshToken = tokens[kRefreshToken];
        } else {
            LogDebug("OIDC refresh token not found in /openid-connect/token response");
        }
    }

    /// Exchange the token with OIDC server.
    void OIDCService::refreshAccessToken() {
        LogTrace("OIDCService::refreshAccessToken");
        unsigned status = kHTTPBadRequest;
        std::promise<void> netPromise;
        auto netFuture = netPromise.get_future();
        std::string responseJson;

        std::string oidcIdP = m_oidcCredentials.getOIDCEndpoint() +
                kKCRealmPath + m_oidcCredentials.getOrgName() + kOIDCTokenPath;

        std::ostringstream tokenBody;

        addFormData(tokenBody, kGrantType, kRefreshToken);
        addFormData(tokenBody, kRefreshToken, m_refreshToken);

        if (m_oidcCredentials.getAuthType() == OIDCCredentials::AuthType::Client) {

            //If we have client creds, send them. This should be optional,
            //and in fact is not part of the OIDC spec, as only the refresh
            //token is required, but Keycloak
            //will optionally take these as well currently.
            if (m_oidcCredentials.getClientId().length() && m_oidcCredentials.getClientSecret().length()) {
                addFormData(tokenBody, kClientID, m_oidcCredentials.getClientId());
                addFormData(tokenBody, kClientSecret, m_oidcCredentials.getClientSecret());
            }
        } else { // assume password
            addFormData(tokenBody, kClientID, m_oidcCredentials.getClientId());
            addFormData(tokenBody, kUsername, m_oidcCredentials.getUsername());
            addFormData(tokenBody, kPassword, m_oidcCredentials.getPassword());
        }

        LogDebug("CredentialsOidc::refreshAccessToken: Sending POST request: " + tokenBody.str());
        m_networkServiceProvider->executePost(
                oidcIdP, {{kContentTypeKey, kContentTypeUrlFormEncode}, {kKeycloakPubkeyHeader, m_clientSigningPubkey}},
                tokenBody.str(), [&netPromise, &responseJson, &status](unsigned int statusCode, std::string &&response) {
                    status = statusCode;
                    responseJson = response;
                    netPromise.set_value();
                });

        // Wait here for a response
        netFuture.get();

        // Handle HTTP error.
        if (!Utils::goodHttpStatus(status)) {
            std::string exceptionMsg = "Get OIDC token failed status: ";
            exceptionMsg += std::to_string(status);
            exceptionMsg += responseJson;
            ThrowException(std::move(exceptionMsg));
        }

        LogDebug("Got OIDC refreshAccessToken response: " + responseJson);

        std::cout << "OIDC Responce :" << responseJson << std::endl;
        auto tokens = nlohmann::json::parse(responseJson);
        if (!tokens.contains(kAccessToken)) {
            std::string exceptionMsg = "OIDC access token not found in /openid-connect/token response";
            ThrowException(std::move(exceptionMsg));
        }

        m_accessToken = tokens[kAccessToken];

        //credential exchange does not always return a refresh token,
        if (tokens.contains(kRefreshToken)) {
            m_refreshToken = tokens[kRefreshToken];
        } else {
            LogDebug("OIDC refresh token not found in /openid-connect/token response");
        }
    }

    /// Check if the access token is valid(check with /userinfo)
    void OIDCService::checkAccessToken()  {
        LogTrace("OIDCService::checkAccessToken");
        unsigned status = kHTTPBadRequest;
        std::promise<void> netPromise;
        auto netFuture = netPromise.get_future();
        std::string responseJson;

        std::string oidcIdP = m_oidcCredentials.getOIDCEndpoint()
                + kKCRealmPath + m_oidcCredentials.getOrgName() + kOIDCUserinfoPath;

        m_networkServiceProvider->executeGet(
                oidcIdP, {{kContentTypeKey, kContentTypeUrlFormEncode},
                          {kAuthorizationKey, std::string(kBearerToken) + std::string(" ") + m_accessToken}},
                [&netPromise, &responseJson, &status](
                        unsigned int statusCode, std::string &&response) {
                    status = statusCode;
                    responseJson = response;
                    netPromise.set_value();
                });

        netFuture.get();

        // Handle HTTP error.
        if (!Utils::goodHttpStatus(status)) {
            std::string exceptionMsg = "Get OIDC userinfo failed status: ";
            exceptionMsg += std::to_string(status);
            exceptionMsg += responseJson;
            ThrowException(std::move(exceptionMsg));
        }

        LogDebug("Got OIDC userInfo response: " + responseJson);

        // Since the response is OK need not parse the response for access token.
        return;
    }

    void OIDCService::addFormData(std::ostringstream &ss, const std::string& key, const std::string& val) {
        //Unless this is the first kvp, append with an ampersand
        if (ss.tellp() != 0) {
            ss << "&";
        }
        ss << Utils::urlEncode(key) << "=" << Utils::urlEncode(val);
    }
}
