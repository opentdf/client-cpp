/*
* Copyright 2021 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
// Created by Sujan Reddy on 7/16/21.
//

#include "oidc_credentials.h"
#include "crypto/crypto_utils.h"
#include "network/network_util.h"
#include "network_interface.h"
#include "nlohmann/json.hpp"
#include "sdk_constants.h"
#include "tdf_exception.h"
#include "utils.h"
#include <algorithm>
#include <cctype>
#include <ctime>
#include <future>
#include <iostream>
#include <logger.h>
#include <regex>
#include <string>
#include <vector>

namespace virtru {

    /// Construcor
    OIDCCredentials::OIDCCredentials() = default;

    /// Constructor
    /// \param openIDConfigurationUrl - The openid configuration url
    OIDCCredentials::OIDCCredentials(const std::string &oidcConfigurationUrl)
            :m_oidcConfigurationUrl(oidcConfigurationUrl) {}

    /// Destructor
    OIDCCredentials::~OIDCCredentials() = default;

    // Provide default implementation.
    OIDCCredentials::OIDCCredentials(const OIDCCredentials &) = default;
    OIDCCredentials &OIDCCredentials::operator=(const OIDCCredentials &) = default;
    OIDCCredentials::OIDCCredentials(OIDCCredentials &&) = default;
    OIDCCredentials &OIDCCredentials::operator=(OIDCCredentials &&) = default;

    /// Set the client credentials that will be use for authn with OIDC server
    void OIDCCredentials::setClientCredentialsClientSecret(const std::string &clientId,
                                                           const std::string &clientSecret,
                                                           const std::string &organizationName,
                                                           const std::string &oidcEndpoint) {
        m_authType = AuthType::ClientSecret;

        m_clientId = clientId;
        m_clientSecret = clientSecret;
        m_orgName = organizationName;
        m_oidcEndpoint = oidcEndpoint;

        LogWarn("This API is deprecated, instead use setClientIdAndClientSecret instead with  OIDCCredentials(configUrl)");
        LogTrace("OIDCCredentials is of auth type client");
    }

    /// Set the client id and client secret that will be use for auth with OIDC server
    void OIDCCredentials::setClientIdAndClientSecret(const std::string &clientId,
                                                     const std::string &clientSecret) {
        m_authType = AuthType::ClientSecret;

        m_clientId = clientId;
        m_clientSecret = clientSecret;

        LogTrace("OIDCCredentials is of auth type client id and client secret");
    }

    /// Set the client credentials that will be use for authn with OIDC server, with an external
    /// token that will be processed and exchanged for a new one.
    void OIDCCredentials::setClientCredentialsTokenExchange(const std::string &clientId,
                                                            const std::string &clientSecret,
                                                            const std::string &externalExchangeToken,
                                                            const std::string &organizationName,
                                                            const std::string &oidcEndpoint) {
        m_authType = AuthType::ExternalExchangeToken;

        m_clientId = clientId;
        m_clientSecret = clientSecret;
        m_orgName = organizationName;
        m_oidcEndpoint = oidcEndpoint;
        m_extToken = externalExchangeToken;

        LogTrace("OIDCCredentials is of auth type client token exchange");
    }

    /// Set the user credentials that will be use for authn with OIDC server
    void OIDCCredentials::setUserCredentialsUser(const std::string &clientId,
                                                 const std::string &username,
                                                 const std::string &password,
                                                 const std::string &organizationName,
                                                 const std::string &oidcEndpoint) {
        m_authType = AuthType::User;

        m_clientId = clientId;
        m_username = username;
        m_password = password;
        m_orgName = organizationName;
        m_oidcEndpoint = oidcEndpoint;

        LogWarn("This API is deprecated, instead use seClientIdAndUserCredentials instead with  OIDCCredentials(configUrl)");
        LogTrace("OIDCCredentials is of auth type user");
    }

    /// Set the client id and user credentials that will be use for authn with OIDC server
    void OIDCCredentials::setClientIdAndUserCredentials(const std::string &clientId,
                                                       const std::string &username,
                                                       const std::string &password) {
        m_authType = AuthType::User;

        m_clientId = clientId;
        m_username = username;
        m_password = password;

        LogTrace("OIDCCredentials is of auth type username and password");
    }

    /// Set the PKI client credentials that will be use for authn with OIDC server
    void OIDCCredentials::setClientCredentialsPKI(const std::string &clientId,
                                                  const std::string &clientKeyFileName,
                                                  const std::string &clientCertFileName,
                                                  const std::string &certificateAuthority,
                                                  const std::string &organizationName,
                                                  const std::string &oidcEndpoint) {

        m_authType = AuthType::PKI;

        m_clientId = clientId;
        m_clientKeyFileName = clientKeyFileName;
        m_clientCertFileName = clientCertFileName;
        m_certificateAuthority = certificateAuthority;
        m_orgName = organizationName;
        m_oidcEndpoint = oidcEndpoint;

        LogWarn("This API is deprecated, instead use setClientIdAndPKI instead with  OIDCCredentials(configUrl)");

        LogTrace("OIDCCredentials is of auth type PKI");
        LogDebug("clientId=" + clientId);
        LogDebug("clientKeyFileName=" + clientKeyFileName);
        LogDebug("clientCertFileName=" + clientCertFileName);
        LogDebug("certificateAuthority=" + certificateAuthority);
        LogDebug("organizationName=" + organizationName);
        LogDebug("oidcEndpoint=" + oidcEndpoint);
    }

    /// Set the client id and PKI client credentials that will be use for auth with OIDC server
    void OIDCCredentials::setClientIdAndPKI(const std::string &clientId,
                                            const std::string &clientKeyFileName,
                                            const std::string &clientCertFileName,
                                            const std::string &certificateAuthority) {
        m_authType = AuthType::PKI;

        m_clientId = clientId;
        m_clientKeyFileName = clientKeyFileName;
        m_clientCertFileName = clientCertFileName;
        m_certificateAuthority = certificateAuthority;
    }

    /// Set the access token that will be used for communicating with the backend.
    void OIDCCredentials::setAccessToken(const std::string &accessToken) {
        m_authType = AuthType::ExternalAccessToken;
        m_accessToken = accessToken;

        LogTrace("OIDCCredentials is of auth type access token");
    }

    /// Return the openid configuration url
    std::string OIDCCredentials::getOIDCConfigurationUrl() const {
        return m_oidcConfigurationUrl;
    }

    /// Return the client id.
    std::string OIDCCredentials::getClientId() const {
        LogTrace("OIDCCredentials::getClientId");
        LogDebug("clientId=" + m_clientId);
        return m_clientId;
    }

    /// Return the client secret.
    std::string OIDCCredentials::getClientSecret() const {
        LogTrace("OIDCCredentials::getClientSecret");
        return m_clientSecret;
    }

    /// Return the externally-provided token to be exchanged as part of client creds auth.
    std::string OIDCCredentials::getExternalExchangeToken() const {
        LogTrace("OIDCCredentials::getExternalExchangeToken");
        return m_extToken;
    }
    /// Return the password for associated user
    std::string OIDCCredentials::getPassword() const {
        LogTrace("OIDCCredentials::getPassword");
        return m_password;
    }

    /// Return the username.
    std::string OIDCCredentials::getUsername() const {
        LogTrace("OIDCCredentials::getUsername");
        LogDebug("username=" + m_username);
        return m_username;
    }

    /// Return the auth type
    /// \return The auth type
    OIDCCredentials::AuthType OIDCCredentials::getAuthType() const {
        LogTrace("OIDCCredentials::getAuthType");
        return m_authType;
    }

    /// Return the OIDC realm or organization the client belongs to
    std::string OIDCCredentials::getOrgName() const {
        LogTrace("OIDCCredentials::getOrgName");
        LogDebug("orgName=" + m_orgName);
        return m_orgName;
    }

    /// Return the OIDC server url
    std::string OIDCCredentials::getOIDCEndpoint() const {
        LogTrace("OIDCCredentials::getOIDCEndpoint");
        LogDebug("oidcEndpoint=" + m_oidcEndpoint);
        return m_oidcEndpoint;
    }

    /// Return the OIDC token ONLY if the user constructed the OIDCCredentials object with token.
    std::string OIDCCredentials::getAccessToken() const {
        LogTrace("OIDCCredentials::getAccessToken");
        return m_accessToken;
    }

    /// Return the description of this object.
    std::string OIDCCredentials::str() const {
        LogTrace("OIDCCredentials::str");
        std::ostringstream osRetval;

        if (m_accessToken.empty()) {
            osRetval << "OIDC Credentials Object ";
            osRetval << " clientId: " << m_clientId;
            osRetval << " oidcEndpoint: " << m_oidcEndpoint;
            osRetval << " orgName: " << m_orgName;
        } else {
            osRetval << "OIDC Credentials Object ";
            osRetval << " accessToken: " << m_accessToken;
        }

        return osRetval.str();
    }

    /// Return the client key file name
    std::string OIDCCredentials::getClientKeyFileName() const {
        LogTrace("OIDCCredentials::getClientKeyFileName");
        LogDebug("clientKeyFileName=" + m_clientKeyFileName);
        return m_clientKeyFileName;
    }

    /// Return the client certificate file name
    std::string OIDCCredentials::getClientCertFileName() const {
        LogTrace("OIDCCredentials::getClientCertFileName");
        LogDebug("clientCertFileName=" + m_clientCertFileName);
        return m_clientCertFileName;
    }

    /// Return the certificate authority
    std::string OIDCCredentials::getCertificateAuthority() const {
        LogTrace("OIDCCredentials::getCertificateAuthority");
        LogDebug("certificateAuthority=" + m_certificateAuthority);
        return m_certificateAuthority;
    }
} // namespace virtru
