//
// Created by Sujan Reddy on 7/16/21.
//

#ifndef VIRTRU_OIDC_CREDENTIALS_H
#define VIRTRU_OIDC_CREDENTIALS_H

#include <string>

namespace virtru {

    // Forward declaration
    class INetwork;

    // OIDC credentials class
    class OIDCCredentials {
    public:
        enum class AuthType {
            Client,
            User,
            PKI,
            AccessToken,
            None
        };
      
    public:
        /// Constructor
        OIDCCredentials();

        /// Destructor
        ~OIDCCredentials();

        /// Assignment operator
        OIDCCredentials& operator=(const OIDCCredentials& oidcCredentials);

        /// Copy constructor
        OIDCCredentials(const OIDCCredentials& oidcCredentials);

        /// Move copy constructor
        OIDCCredentials(OIDCCredentials && oidcCredentials);

        /// Move assignment operator
        OIDCCredentials& operator=(OIDCCredentials && oidcCredentials);

    public: // Public methods
        /// Set the client credentials that will be use for authz with OIDC server
        /// \param clientId - The client id
        /// \param clientSecret - The client secret
        /// \param organizationName - The OIDC realm or organization the client belongs to
        /// \param oidcEndpoint - The OIDC server url
        void setClientCredentials(const std::string &clientId,
                                  const std::string &clientSecret,
                                  const std::string &organizationName,
                                  const std::string &oidcEndpoint);

        /// Return the client id.
        /// \return - The client id as string
        std::string getClientId() const;

        /// Return the client secret.
        /// \return - The client secret as string
        std::string getClientSecret() const;

        /// Return the password for associated user
        /// \return - The password for associated user
        std::string getPassword() const;

        /// Return the username.
        /// \return - The username
        std::string getUsername() const;

        /// Return the auth type
        /// \return The auth type
        AuthType getAuthType() const;

        /// Return the OIDC realm or organization the client belongs to
        /// \return - The OIDC realm or organization as string
        std::string getOrgName() const;

        /// Return the OIDC server url
        /// \return - The OIDC server url as string
        std::string getOIDCEndpoint() const;

        /// Return the OIDC token ONLY if the user constructed the OIDCCredentials object with token.
        /// \return - The OIDC token and set it as the Bearer token for all requests this client will make.
        std::string getAccessToken() const;

        /// Return the description of this object.
        /// \return The description of this object.
        std::string str() const;

    private: // Disable the PE support for now
        /// Set the user credentials that will be use for authz with OIDC server
        /// \param clientId - The client id
        /// \param username - The registered username
        /// \param password - The password associated with the user
        /// \param organizationName - The OIDC realm or organization the client belongs to
        /// \param oidcEndpoint - The OIDC server url
        void setUserCredentials(const std::string &clientId,
                                const std::string &username,
                                const std::string &password,
                                const std::string &organizationName,
                                const std::string &oidcEndpoint);

        /// Set the access token that will be used for communicating with the backend.
        /// \param accessToken - The OIDC token and set it as the Bearer token for all requests this client will make.
        void setAccessToken(const std::string &accessToken);


    private: // Data
        std::string m_clientId;
        std::string m_clientSecret;
        std::string m_username;
        std::string m_password;
        std::string m_orgName;
        std::string m_oidcEndpoint;
        std::string m_accessToken;
        AuthType m_authType{AuthType::None};
    };
}
#endif //VIRTRU_OIDC_CREDENTIALS_H