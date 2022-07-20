/*
 * Copyright 2019 Virtru Corporation
 *
 * SPDX - License Identifier: BSD-3-Clause-Clear
 *
 */
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/05/15.
//

#ifndef VIRTRU_NETWORK_INTERFACE_H
#define VIRTRU_NETWORK_INTERFACE_H

#include "map"
#include "tuple"
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include "numeric"

namespace virtru {

    // Http headers
    using HttpHeaders = std::unordered_map<std::string, std::string>;

    // callback once the http request is completed.
    using HTTPServiceCallback = std::function<void(unsigned int statusCode, std::string &&response)>;

    /// An interface for handling network request.
    ///
    /// If the consumer wants to provide their own network interface, this interface needs to implemented.
    ///
    class INetwork {
        public:
            virtual ~INetwork() = default;
            /// Execute a get request and on completion the callback is executed.
            /// \param url - The url (e.g., "https://developer.virtru.com/docs/sdk").
            /// \param headers - The http headers used by network service when performing HTTP operation.
            /// \param callback - The response callback.
            virtual void executeGet(const std::string &url, const HttpHeaders &headers, HTTPServiceCallback &&callback,
                                    const std::string &certAuth = "", const std::string &clientKeyFileName = "", const std::string &clientCertFileName = "") = 0;

            /// Execute a put request and on completion the callback is executed.
            /// \param url - The url (e.g., "https://api.virtru.com/api/entityobject").
            /// \param headers - The http headers used by network service when performing HTTP operation.
            /// \param body - The HTTP body part of the request
            /// \param callback - The response callback.
            virtual void executePut(const std::string &url, const HttpHeaders &headers, std::string &&body, HTTPServiceCallback &&callback,
                                 const std::string &certAuth = "", const std::string &clientKeyFileName = "", const std::string &clientCertFileName = "") = 0;

            /// Execute a post request and on completion the callback is executed.
            /// \param url - The url (e.g., "https://api.virtru.com/api/entityobject").
            /// \param headers - The http headers used by network service when performing HTTP operation.
            /// \param body - The HTTP body part of the request
            /// \param callback - The response callback.
            virtual void executePost(const std::string &url, const HttpHeaders &headers, std::string &&body, HTTPServiceCallback &&callback,
                                     const std::string &certAuth = "", const std::string &clientKeyFileName = "", const std::string &clientCertFileName = "") = 0;

            /// Execute a patch request and on completion the callback is executed.
            /// \param url - The url (e.g., "https://api.virtru.com/api/policies").
            /// \param headers - The http headers used by network service when performing HTTP operation.
            /// \param body - The HTTP body part of the request
            /// \param callback - The response callback.
            virtual void executePatch(const std::string &url, const HttpHeaders &headers, std::string &&body, HTTPServiceCallback &&callback,
                                      const std::string &certAuth = "", const std::string &clientKeyFileName = "", const std::string &clientCertFileName = "") = 0;

            /// Execute a head request and on completion the callback is executed.
            /// \param url - The url (e.g., "https://developer.virtru.com/docs/sdk").
            /// \param headers - The http headers used by network service when performing HTTP operation.
            /// \param callback - The response callback.
            virtual void executeHead(const std::string &url, const HttpHeaders &headers, HTTPServiceCallback &&callback,
                                    const std::string &certAuth = "", const std::string &clientKeyFileName = "", const std::string &clientCertFileName = "") = 0;

    };

} // namespace virtru

#endif //VIRTRU_NETWORK_INTERFACE_H
