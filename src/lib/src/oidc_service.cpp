/*
* Copyright 2021 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
// Created by Sujan Reddy on 7/16/21.
//

#include "nlohmann/json.hpp"
#include <future>
#include <iostream>
#include <utility>

#include "crypto/crypto_utils.h"
#include "network/http_service_provider.h"
#include "oidc_service.h"
#include "sdk_constants.h"
#include "tdf_exception.h"
#include "utils.h"
#include <jwt-cpp/jwt.h>
#include <boost/exception/diagnostic_information.hpp>
#include "oidc_configuration.h"

namespace virtru {

    using namespace virtru::network;

    using namespace virtru::crypto;

    /// Constructor
    OIDCService::OIDCService(OIDCCredentials oidcCredentials,
                             const std::string &clientSigningPubkey,
                             std::shared_ptr<INetwork> httpServiceProvider)
        : m_oidcCredentials(std::move(oidcCredentials)),
          m_networkServiceProvider(std::move(httpServiceProvider)) {
        LogTrace("OIDCService::OIDCService");

        m_clientSigningPubkey = base64UrlEncode(clientSigningPubkey);
    }

    /// Create the header key/value pairs that should be added to the request to establish authorization
    std::map<std::string, std::string> OIDCService::generateAuthHeaders() {

        LogTrace("OIDCService::generateAuthHeaders");

        std::ostringstream authHeaderStream;
        std::map<std::string, std::string> authHeader;

        if (m_oidcCredentials.getAuthType() == OIDCCredentials::AuthType::None) {
            ThrowException("OIDC credentials are missing");
        }

        // If the credentials object already have an access token, use it.
        if (m_oidcCredentials.getAuthType() == OIDCCredentials::AuthType::ClientSecret ||
            m_oidcCredentials.getAuthType() == OIDCCredentials::AuthType::ExternalExchangeToken ||
            m_oidcCredentials.getAuthType() == OIDCCredentials::AuthType::PKI ||
            m_oidcCredentials.getAuthType() == OIDCCredentials::AuthType::User) {
            getAccessToken();
            authHeaderStream << kBearerToken << " " << m_accessToken;
            LogDebug("Access token added to auth header");

            authHeader.insert({kAuthorizationKey, authHeaderStream.str()});
        } else if (m_oidcCredentials.getAuthType() == OIDCCredentials::AuthType::ExternalAccessToken) {
            m_accessToken = m_oidcCredentials.getAccessToken();
            authHeaderStream << kBearerToken << " " << m_accessToken;
            authHeader.insert({kAuthorizationKey, authHeaderStream.str()});
        } else {
            ThrowException("OIDC auth type not supported");
        }

        auto decoded_token = jwt::decode(m_accessToken);
        nlohmann::json tokenAsJson = nlohmann::json::parse(decoded_token.get_payload());
        m_preferredUsername = tokenAsJson[kPreferredUsername];

        LogDebug("Preferred username: " + m_preferredUsername);
        LogDebug("Authorization = " + authHeaderStream.str());
        return authHeader;
    }

    // Return the attributes that are in claims object(part of access token)
    std::vector<std::string> OIDCService::getClaimsObjectAttributes() {

        LogTrace("OIDCService::getClaimsObjectAttributes");

        if (m_accessToken.empty()) {
            ThrowException("Access token missing from OIDC service", VIRTRU_NETWORK_ERROR);
        }

        auto decoded_token = jwt::decode(m_accessToken);
        nlohmann::json tokenAsJson = nlohmann::json::parse(decoded_token.get_payload());
        nlohmann::json subjectAttributes = nlohmann::json::array();
        subjectAttributes = tokenAsJson[kTDFClaims][kSubjectAttributes];

        std::vector<std::string> attributes;
        attributes.reserve(subjectAttributes.size());
        for (const auto &subjectAttribute : subjectAttributes) {
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

        LogTrace("OIDCService::getAccessToken");

        if (m_accessToken.empty()) {
            //We don't have cached tokens, fetch
            LogDebug("fetching initial access token");
            fetchAccessToken();
        } else {
            //First, try to grab the cached accessToken
            //and hit up the userinfo endpoint with it
            try {
                LogDebug("Checking token");
                checkAccessToken();
                //That worked? Cool, token is still valid, return
                LogDebug("Access token valid");
            } catch (const Exception &exception) {
                LogWarn("UserInfo request failed, attempting refresh");
                try {

                    // Get a new access token using the refresh token
                    if (!m_refreshToken.empty()) {
                        LogDebug("Refreshing access token");
                        refreshAccessToken();
                    } else {
                        LogDebug("Fetching access token");
                        fetchAccessToken();
                    }
                } catch (const Exception &refreshException) {
                    LogWarn("Refresh token rejected, attempting to regenerate tokens with credentials");
                    //Last-ditch effort, maybe our client creds are still valid even if
                    //our refresh and access tokens aren't - try to fetch a new tokenset from scratch
                    LogDebug("fetching replacement access token");
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
        std::string oidcIdP = getOIDCUrl();

        if (m_oidcCredentials.getAuthType() == OIDCCredentials::AuthType::ClientSecret) {
            LogDebug("AuthType:ClientSecret");
            addFormData(tokenBody, kGrantType, kClientCredentials);
            addFormData(tokenBody, kClientID, m_oidcCredentials.getClientId());
            addFormData(tokenBody, kClientSecret, m_oidcCredentials.getClientSecret());
        } else if (m_oidcCredentials.getAuthType() == OIDCCredentials::AuthType::ExternalExchangeToken) {
            LogDebug("AuthType:ExternalExchangeToken");
            addFormData(tokenBody, kGrantType, kExchangeToken);
            addFormData(tokenBody, kClientID, m_oidcCredentials.getClientId());
            addFormData(tokenBody, kClientSecret, m_oidcCredentials.getClientSecret());
            addFormData(tokenBody, kSubjectToken, m_oidcCredentials.getExternalExchangeToken());
            addFormData(tokenBody, kTokenRequestType, kTokenRequestAccess);
        } else if (m_oidcCredentials.getAuthType() == OIDCCredentials::AuthType::PKI) {
            LogDebug("AuthType:PKI");
            addFormData(tokenBody, kGrantType, kPasswordCredentials);
            addFormData(tokenBody, kClientID, m_oidcCredentials.getClientId());
            // The username will be pulled from the certificate used to establish the mTLS connection
            // and the password is obsoleted by the mTLS trust, but the fields need to exist to satisfy
            // the request parser
            addFormData(tokenBody, kUsername, "");
            addFormData(tokenBody, kPassword, "");
        } else { // assume password
            LogDebug("AuthType:Password");
            addFormData(tokenBody, kUsername, m_oidcCredentials.getUsername());
            addFormData(tokenBody, kPassword, m_oidcCredentials.getPassword());
            addFormData(tokenBody, kGrantType, kPasswordCredentials);
            addFormData(tokenBody, kClientID, m_oidcCredentials.getClientId());
        }

        std::string certAuthority = "";
        std::string clientKeyFileName = "";
        std::string clientCertFileName = "";
        if (m_oidcCredentials.getAuthType() == OIDCCredentials::AuthType::PKI) {
            clientKeyFileName = m_oidcCredentials.getClientKeyFileName();
            clientCertFileName = m_oidcCredentials.getClientCertFileName();
            certAuthority = m_oidcCredentials.getCertificateAuthority();
        }

        LogDebug("OIDCService::fetchAccessToken: Sending POST request: " + tokenBody.str());

        m_networkServiceProvider->executePost(
                oidcIdP, {{kContentTypeKey, kContentTypeUrlFormEncode}, {kKeycloakPubkeyHeader, m_clientSigningPubkey}},
                tokenBody.str(),
                [&netPromise, &responseJson, &status](unsigned int statusCode, std::string &&response) {
                    status = statusCode;
                    responseJson = response;
                    netPromise.set_value();
                },
                certAuthority,
                clientKeyFileName,
                clientCertFileName);

        // Wait here for a response
        netFuture.get();

        // Handle HTTP error.
        if (!Utils::goodHttpStatus(status)) {
            std::string exceptionMsg = "Get OIDC token failed status: ";
            exceptionMsg += std::to_string(status);
            exceptionMsg += " - ";
            exceptionMsg += responseJson;
            LogDebug("Bad http response: " + exceptionMsg);
            ThrowException(std::move(exceptionMsg), VIRTRU_NETWORK_ERROR);
        }

        LogDebug("Got OIDC fetchAccessToken response: " + responseJson);
        nlohmann::json tokens;

        try{
            tokens = nlohmann::json::parse(responseJson);
        } catch (...) {
            if (responseJson == ""){
                ThrowException("No fetchAccessToken response from OIDC service", VIRTRU_NETWORK_ERROR);
            }
            else{
                ThrowException("Could not parse OIDC fetchAccessToken response: " + boost::current_exception_diagnostic_information() + "  with response: " + responseJson, VIRTRU_NETWORK_ERROR);
            }
        }

        if (!tokens.contains(kAccessToken)) {
            std::string exceptionMsg = "OIDC access token not found in /openid-connect/token response";
            ThrowException(std::move(exceptionMsg), VIRTRU_NETWORK_ERROR);
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

        std::string oidcIdP = getOIDCUrl();
        std::ostringstream tokenBody;

        addFormData(tokenBody, kGrantType, kRefreshToken);
        addFormData(tokenBody, kRefreshToken, m_refreshToken);

        if (m_oidcCredentials.getAuthType() == OIDCCredentials::AuthType::ClientSecret) {

            //If we have client creds, send them. This should be optional,
            //and in fact is not part of the OIDC spec, as only the refresh
            //token is required, but Keycloak
            //will optionally take these as well currently.
            if (m_oidcCredentials.getClientId().length() && m_oidcCredentials.getClientSecret().length()) {
                addFormData(tokenBody, kClientID, m_oidcCredentials.getClientId());
                addFormData(tokenBody, kClientSecret, m_oidcCredentials.getClientSecret());
            }
        } else if (m_oidcCredentials.getAuthType() == OIDCCredentials::AuthType::PKI) {
            addFormData(tokenBody, kClientID, m_oidcCredentials.getClientId());
            // The username will be pulled from the certificate used to establish the mTLS connection
            // and the password is obsoleted by the mTLS trust, but the fields need to exist to satisfy
            // the request parser
            addFormData(tokenBody, kUsername, "");
            addFormData(tokenBody, kPassword, "");
        } else { // assume password
            addFormData(tokenBody, kClientID, m_oidcCredentials.getClientId());
            addFormData(tokenBody, kUsername, m_oidcCredentials.getUsername());
            addFormData(tokenBody, kPassword, m_oidcCredentials.getPassword());
        }

        std::string certAuthority = "";
        std::string clientKeyFileName = "";
        std::string clientCertFileName = "";
        if (m_oidcCredentials.getAuthType() == OIDCCredentials::AuthType::PKI) {
            clientKeyFileName = m_oidcCredentials.getClientKeyFileName();
            clientCertFileName = m_oidcCredentials.getClientCertFileName();
            certAuthority = m_oidcCredentials.getCertificateAuthority();
        }

        LogDebug("CredentialsOidc::refreshAccessToken: Sending POST request: " + tokenBody.str());

        m_networkServiceProvider->executePost(
                oidcIdP,
                {{kContentTypeKey, kContentTypeUrlFormEncode},
                 {kKeycloakPubkeyHeader, m_clientSigningPubkey}},
                tokenBody.str(), [&netPromise, &responseJson, &status](unsigned int statusCode, std::string &&response) {
                    status = statusCode;
                    responseJson = response;
                    netPromise.set_value();
                },
                certAuthority, clientKeyFileName, clientCertFileName);

        // Wait here for a response
        netFuture.get();

        // Handle HTTP error.
        if (!Utils::goodHttpStatus(status)) {
            std::string exceptionMsg = "Get OIDC token failed status: ";
            exceptionMsg += std::to_string(status);
            exceptionMsg += " - ";
            exceptionMsg += responseJson;
            ThrowException(std::move(exceptionMsg), VIRTRU_NETWORK_ERROR);
        }

        LogDebug("Got OIDC refreshAccessToken response: " + responseJson);
        nlohmann::json tokens;
        try{
            tokens = nlohmann::json::parse(responseJson);
        } catch (...){
            if (responseJson == ""){
                ThrowException("No refreshAccessToken response from OIDC service", VIRTRU_NETWORK_ERROR);
            }
            else{
                ThrowException("Could not parse OIDC refreshAccessToken response: " + boost::current_exception_diagnostic_information() + "  with response: " + responseJson, VIRTRU_NETWORK_ERROR);
            }
        }
        
        if (!tokens.contains(kAccessToken)) {
            std::string exceptionMsg = "OIDC access token not found in /openid-connect/token response";
            ThrowException(std::move(exceptionMsg), VIRTRU_NETWORK_ERROR);
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
    void OIDCService::checkAccessToken() {
        LogTrace("OIDCService::checkAccessToken");

        unsigned status = kHTTPBadRequest;
        std::promise<void> netPromise;
        auto netFuture = netPromise.get_future();
        std::string responseJson;

        std::string oidcIdP = getOIDCUrl();
        std::string certAuthority = "";
        std::string clientKeyFileName = "";
        std::string clientCertFileName = "";
        if (m_oidcCredentials.getAuthType() == OIDCCredentials::AuthType::PKI) {
            clientKeyFileName = m_oidcCredentials.getClientKeyFileName();
            clientCertFileName = m_oidcCredentials.getClientCertFileName();
            certAuthority = m_oidcCredentials.getCertificateAuthority();
        }

        m_networkServiceProvider->executeGet(
                oidcIdP, {{kContentTypeKey, kContentTypeUrlFormEncode}, {kAuthorizationKey, std::string(kBearerToken) + std::string(" ") + m_accessToken}},
                [&netPromise, &responseJson, &status](
                    unsigned int statusCode, std::string &&response) {
                    status = statusCode;
                    responseJson = response;
                    netPromise.set_value();
                },
                certAuthority,
                clientKeyFileName,
                clientCertFileName);

        netFuture.get();

        // Handle HTTP error.
        if (!Utils::goodHttpStatus(status)) {
            std::string exceptionMsg = "Get OIDC userinfo failed status: ";
            exceptionMsg += std::to_string(status);
            exceptionMsg += " - ";
            exceptionMsg += responseJson;
            ThrowException(std::move(exceptionMsg), VIRTRU_NETWORK_ERROR);
        }

        LogDebug("Got OIDC userInfo response: " + responseJson);

        // Since the response is OK need not parse the response for access token.
        return;
    }

    /// Get the OIDC url for fetching access token.
    std::string OIDCService::getOIDCUrl() {

        auto openIdConfigUrl = m_oidcCredentials.getOpenIDConfigurationUrl();
        if (openIdConfigUrl.empty()) {
            auto oidcEndpoint =  m_oidcCredentials.getOIDCEndpoint();
            if('/' == oidcEndpoint.back()) {
                oidcEndpoint.pop_back();
            }

            std::string oidcUrl = oidcEndpoint + kKCRealmPath + m_oidcCredentials.getOrgName() + kOIDCTokenPath;
            return oidcUrl;
        } else {
            OpenIDConfiguration openIdConfiguration{openIdConfigUrl};
            return openIdConfiguration.getOIDCUrl();
        }
    }

    void OIDCService::addFormData(std::ostringstream &ss, const std::string &key, const std::string &val) {
        LogTrace("OIDCService::addFormData");

        //Unless this is the first kvp, append with an ampersand
        if (ss.tellp() != 0) {
            ss << "&";
        }
        ss << Utils::urlEncode(key) << "=" << Utils::urlEncode(val);
    }
} // namespace virtru
