//
// Created by Sujan Reddy on 7/16/21.
//

#include <algorithm>
#include <cctype>
#include <ctime>
#include <future>
#include <iostream>
#include <logger.h>
#include <regex>
#include <string>
#include <tao/json.hpp>
#include <vector>
#include "oidc_credentials.h"
#include "utils.h"
#include "crypto/crypto_utils.h"
#include "network/network_util.h"
#include "network_interface.h"
#include "sdk_constants.h"
#include "tdf_exception.h"

namespace virtru {

    /// Construcor
    OIDCCredentials::OIDCCredentials() = default;

    /// Destructor
    OIDCCredentials::~OIDCCredentials() = default;

    // Provide default implementation.
    OIDCCredentials::OIDCCredentials(const OIDCCredentials&) = default;
    OIDCCredentials& OIDCCredentials::operator=(const OIDCCredentials&) = default;
    OIDCCredentials::OIDCCredentials(OIDCCredentials&&) = default;
    OIDCCredentials& OIDCCredentials::operator=(OIDCCredentials&&) = default;

    /// Set the client credentials that will be use for authz with OIDC server
    void OIDCCredentials::setClientCredentials(const std::string &clientId,
                                               const std::string &clientSecret,
                                               const std::string &organizationName,
                                               const std::string &oidcEndpoint) {
        m_authType = AuthType::Client;
        m_clientId = clientId;
        m_clientSecret = clientSecret;
        m_orgName = organizationName;
        m_oidcEndpoint = oidcEndpoint;

        LogTrace("OIDCCredentials is of auth type as client");
    }

    /// Set the user credentials that will be use for authz with OIDC server
    void OIDCCredentials::setUserCredentials(const std::string &clientId,
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

        LogTrace("OIDCCredentials is of auth type as user");
    }

    /// Set the access token that will be used for communicating with the backend.
    void OIDCCredentials::setAccessToken(const std::string &accessToken) {
        m_authType = AuthType::AccessToken;
        m_accessToken = accessToken;

        LogTrace("OIDCCredentials is of auth type as as access token");
    }

    /// Return the client id.
    std::string OIDCCredentials::getClientId() const {
        return m_clientId;
    }

    /// Return the client secret.
    std::string OIDCCredentials::getClientSecret() const {
        return m_clientSecret;
    }

    /// Return the password for associated user
    std::string OIDCCredentials::getPassword() const {
        return m_password;
    }

    /// Return the username.
    std::string OIDCCredentials::getUsername() const {
        return m_username;
    }

    /// Return the auth type
    /// \return The auth type
    OIDCCredentials::AuthType OIDCCredentials::getAuthType() const {
        return m_authType;
    }

    /// Return the OIDC realm or organization the client belongs to
    std::string OIDCCredentials::getOrgName() const {
        return m_orgName;
    }

    /// Return the OIDC server url
    std::string OIDCCredentials::getOIDCEndpoint() const {
        return m_oidcEndpoint;
    }

    /// Return the OIDC token ONLY if the user constructed the OIDCCredentials object with token.
    std::string OIDCCredentials::getAccessToken() const {
        return m_accessToken;
    }

    /// Return the description of this object.
    std::string OIDCCredentials::str() const {
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
}