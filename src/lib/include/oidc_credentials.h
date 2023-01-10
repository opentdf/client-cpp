/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
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
            ClientSecret,
            User,
            PKI,
            ExternalAccessToken,
            ExternalExchangeToken,
            None
        };

      public:
        /// Constructor
        OIDCCredentials();

        /// Constructor
        /// \param OIDCConfigurationUrl - The openid configuration url
        OIDCCredentials(const std::string &oidcConfigurationUrl);

        /// Destructor
        ~OIDCCredentials();

        /// Assignment operator
        OIDCCredentials &operator=(const OIDCCredentials &oidcCredentials);

        /// Copy constructor
        OIDCCredentials(const OIDCCredentials &oidcCredentials);

        /// Move copy constructor
        OIDCCredentials(OIDCCredentials &&oidcCredentials);

        /// Move assignment operator
        OIDCCredentials &operator=(OIDCCredentials &&oidcCredentials);

      public: // Public methods
        /// Set the secret client credentials that will be use for auth with OIDC server
        /// \param clientId - The client id
        /// \param clientSecret - The client secret
        /// \param organizationName - The OIDC realm or organization the client belongs to
        /// \param oidcEndpoint - The OIDC server url
        void setClientCredentialsClientSecret(const std::string &clientId,
                                              const std::string &clientSecret,
                                              const std::string &organizationName,
                                              const std::string &oidcEndpoint);

        /// Set the client id and client secret that will be use for auth with OIDC server
        /// \param clientId - The client id
        /// \param clientSecret - The client secret
        void setClientIdAndClientSecret(const std::string &clientId,
                                        const std::string &clientSecret);

        /// Set the secret client credentials and external exchange token
        /// that will be used for authn with OIDC server
        /// \param clientId - The client id
        /// \param clientSecret - The client secret
        /// \param externalExchangeToken - An external token
        /// \param organizationName - The OIDC realm or organization the client belongs to
        /// \param oidcEndpoint - The OIDC server url
        void setClientCredentialsTokenExchange(const std::string &clientId,
                                               const std::string &clientSecret,
                                               const std::string &externalExchangeToken,
                                               const std::string &organizationName,
                                               const std::string &oidcEndpoint);



        /// Set the PKI client credentials that will be use for authn with OIDC server
        /// \param clientId - The client id
        /// \param clientKeyFileName - The name of the file containing the client key
        /// \param clientCertFileName - The name of the file containing the client certificate
        /// \param certificateAuthority - The certificate authority to be used
        /// \param organizationName - The OIDC realm or organization the client belongs to
        /// \param oidcEndpoint - The OIDC server url
        void setClientCredentialsPKI(const std::string &clientId,
                                     const std::string &clientKeyFileName,
                                     const std::string &clientCertFileName,
                                     const std::string &certificateAuthority,
                                     const std::string &organizationName,
                                     const std::string &oidcEndpoint);


        /// Set the client id and PKI client credentials that will be use for auth with OIDC server
        /// \param clientId - The client id
        /// \param clientKeyFileName - The name of the file containing the client key
        /// \param clientCertFileName - The name of the file containing the client certificate
        /// \param certificateAuthority - The certificate authority to be used
        void setClientIdAndPKI(const std::string &clientId,
                               const std::string &clientKeyFileName,
                               const std::string &clientCertFileName,
                               const std::string &certificateAuthority);

        /// Set the user credentials that will be use for authn with OIDC server
        /// \param clientId - The client id
        /// \param username - The registered username
        /// \param password - The password associated with the user
        /// \param organizationName - The OIDC realm or organization the client belongs to
        /// \param oidcEndpoint - The OIDC server url
        void setUserCredentialsUser(const std::string &clientId,
                                    const std::string &username,
                                    const std::string &password,
                                    const std::string &organizationName,
                                    const std::string &oidcEndpoint);


        /// Set the client id and user credentials that will be use for authn with OIDC server
        /// \param clientId - The client id
        /// \param username - The registered username
        /// \param password - The password associated with the user
        void setClientIdAndUserCredentials(const std::string &clientId,
                                           const std::string &username,
                                           const std::string &password);


        /// Return the openid configuration url
        /// \return  - The openid configuration url
        std::string getOIDCConfigurationUrl() const;

        /// Return the client id.
        /// \return - The client id as string
        std::string getClientId() const;

        /// Return the client secret.
        /// \return - The client secret as string
        std::string getClientSecret() const;

        /// Return the password for associated user
        /// \return - The password for associated user
        std::string getPassword() const;

        /// Returns the externally-provided token that will be included
        /// in the client credential auth flow and exchanged for a new token.
        /// \return - The external OIDC token to exchange
        std::string getExternalExchangeToken() const;

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

        /// Return the client key file name
        /// \return - The client key file name as string
        std::string getClientKeyFileName() const;

        /// Return the client certificate file name
        /// \return - The client certificate file name as string
        std::string getClientCertFileName() const;

        /// Return the certificate authority
        /// \return - The certificate authority as string
        std::string getCertificateAuthority() const;

        /// Return the description of this object.
        /// \return The description of this object.
        std::string str() const;

      private:
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
        std::string m_clientKeyFileName;
        std::string m_clientCertFileName;
        std::string m_certificateAuthority;
        std::string m_extToken;
        std::string m_accessToken;
        std::string m_oidcConfigurationUrl;
        AuthType m_authType{AuthType::None};
    };
} // namespace virtru
#endif //VIRTRU_OIDC_CREDENTIALS_H
