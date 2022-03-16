/*
* Copyright 2021 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
// Created by Sujan Reddy on 7/17/21.
//

#ifndef VIRTRU_NETWORK_SERVICE_PROVIDER_H
#define VIRTRU_NETWORK_SERVICE_PROVIDER_H

#include "oidc_credentials.h"
#include "network_interface.h"
#include "http_client_service.h"

namespace virtru::network {

    class HTTPServiceProvider : public INetwork {
    public: /// Interface
        /// Constructor
        explicit HTTPServiceProvider(HttpHeaders headers);

        /// Destructor
        ~HTTPServiceProvider() override = default;

        /// Provide default implementation since there is not much state to this instance.
        HTTPServiceProvider(const HTTPServiceProvider &) = default;
        HTTPServiceProvider(HTTPServiceProvider &&) = default;
        HTTPServiceProvider & operator=(const HTTPServiceProvider &) = default;
        HTTPServiceProvider & operator=(HTTPServiceProvider &&) = default;

    public: // INetwork
        /// Execute a get request and on completion the callback is executed.
        /// \param url - The url (e.g., "https://developer.virtru.com/docs/sdk").
        /// \param headers - The http headers used by network service when performing HTTP operation.
        /// \param callback - The response callback.
        /// \param sdkCertAuthority - certificate authority to use - optional
        /// \param clientKeyFileName - file containing client key to use - optional
        /// \param clientCertFileName - file containing client certificate to use - optional
        void executeGet(const std::string& url,
                        const HttpHeaders& headers,
                        HTTPServiceCallback&& callback,
                        const std::string& sdkCertAuthority = "",
                        const std::string& clientKeyFileName = "",
                        const std::string& clientCertFileName = "") override;


        /// Execute a post request and on completion the callback is executed.
        /// \param url - The url (e.g., "https://api.virtru.com/api/entityobject").
        /// \param headers - The http headers used by network service when performing HTTP operation.
        /// \param body - The HTTP body part of the request
        /// \param callback - The response callback.
        /// \param sdkCertAuthority - certificate authority to use - optional
        /// \param clientKeyFileName - file containing client key to use - optional
        /// \param clientCertFileName - file containing client certificate to use - optional
        void executePost(const std::string& url,
                         const HttpHeaders& headers,
                         std::string&& body,
                         HTTPServiceCallback&& callback,
                         const std::string& sdkCertAuthority = "",
                         const std::string& clientKeyFileName = "",
                         const std::string& clientCertFileName = "") override;


        /// Execute a patch request and on completion the callback is executed.
        /// \param url - The url (e.g., "https://api.virtru.com/api/policies").
        /// \param headers - The http headers used by network service when performing HTTP operation.
        /// \param body - The HTTP body part of the request
        /// \param callback - The response callback.
        /// \param sdkCertAuthority - certificate authority to use - optional
        /// \param clientKeyFileName - file containing client key to use - optional
        /// \param clientCertFileName - file containing client certificate to use - optional
        void executePatch(const std::string& url,
                          const HttpHeaders& headers,
                          std::string&& body,
                          HTTPServiceCallback&& callback,
                          const std::string& sdkCertAuthority = "",
                          const std::string& clientKeyFileName = "",
                          const std::string& clientCertFileName = "") override;


    private:
        /// Update the service with authorization header and other required headers.
        /// \param service - The server object
        /// \param httpVerb - The HTTP Verb
        /// \param headers - The HTTP header that needs to be added to the service object
        /// \param body - The Request body
        /// \param url - The server url
        void updateService(Service &service, const std::string &httpVerb,
                           const HttpHeaders &headers, const std::string &body,
                           const std::string &url);

    private:
        HttpHeaders m_httpHeaders;
    };
}

#endif //VIRTRU_NETWORK_SERVICE_PROVIDER_H
