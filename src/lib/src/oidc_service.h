/*
* Copyright 2021 Virtru Corporation
*
* SPDX - License - Identifier: MIT
*
*/
//
// Created by Sujan Reddy on 7/16/21.
//

#ifndef VIRTRU_NETWORK_OIDC_SERVICE_H
#define VIRTRU_NETWORK_OIDC_SERVICE_H

#include <map>
#include "oidc_credentials.h"

namespace virtru {

    class OIDCService {

    public:
        /// Constructor
        OIDCService(OIDCCredentials oidcCredentials,
                    const HttpHeaders& headers,
                    const std::string& clientPubKey);

        /// Destructor
        ~OIDCService() = default;

        /// Copy constructor
        OIDCService(const OIDCService &oidcService) = delete;

        /// Assignment operator
        OIDCService &operator=(const OIDCService &oidcService) = delete;

        /// Move copy constructor
        OIDCService(OIDCService &&oidcService) = delete;

        /// Move assignment operator
        OIDCService &operator=(OIDCService &&oidcService) = delete;

    public: // Interface
        /// Create the header key/value pairs that should be added to the request to
        /// establish authorization
        std::map<std::string, std::string> generateAuthHeaders();

        // Return the attributes that are in claims object(part of access token)
        /// \return - The attributes as strings in a vector
        std::vector<std::string> getClaimsObjectAttributes();

        /// Return the preferred username
        /// \return The preferred username
        std::string getPreferredUsername() const { return m_preferredUsername; }

    private:
        /// Refresh the access token.
        void refreshAccessToken();

        /// Exchange the credentials with OIDC server and fetch the access token
        /// \return - The access token
        void fetchAccessToken();

        /// Check if the access token is valid(check with /userinfo)
        void checkAccessToken();

        /// Get the access token from the OIDC server.
        void getAccessToken();

        /// Add form data to the string stream.
        static void addFormData(std::ostringstream &ss, const std::string& key, const std::string& val) ;

    private:
        std::string m_preferredUsername;
        std::string m_clientSigningPubkey;
        std::string m_accessToken;
        std::string m_refreshToken;
        OIDCCredentials m_oidcCredentials;
        std::tuple<std::string, std::string> m_tokens;
        std::unique_ptr<INetwork> m_networkServiceProvider;
    };
}

#endif //VIRTRU_NETWORK_OIDC_SERVICE_H
