/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License - Identifier: MIT
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/04.
//

#ifndef VIRTRU_HTTP_CLIENT_SERVICE_H
#define VIRTRU_HTTP_CLIENT_SERVICE_H

#include "tdf_exception.h"

#include <string>
#include <memory>
#include <type_traits>
#include <boost/beast.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/core.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/beast/core/buffers_to_string.hpp>

namespace virtru::network {

    namespace bb = boost::beast;
    namespace ba = boost::asio;
    namespace bs = boost::system;

    using HttpRequest = bb::http::request<bb::http::string_body>;
    using HttpResponse = bb::http::response<bb::http::string_body>;
    using ErrorCode = boost::system::error_code;
    using SSLContext = ba::ssl::context;
    using IOContext = ba::io_context;
    using HttpVerb = bb::http::verb;
    using HttpField = bb::http::field;

    // Asynchronous callback once the http request is completed.
    using ServiceCallback = std::function<void (ErrorCode errorCode, HttpResponse&& response)>;

    /// This is HTTP service class responsible for performing asynchronous http operations. It also provides
    /// abstraction layer on of top Boost framework(which is namespace mess).
    class Service {
    public: // Interface

        /// Create an instance of Service and returns a unique_ptr. On error it throws exception
        /// \param url - The url (e.g., "https://developer.virtru.com/docs/sdk").
        ///              NOTE: It expects '(http|https)//<domain>/<target>'
        ///              The target string (e.g., /forum/questions/?tag=networking&order=newest#top ->
        ///              path+query+fragment).
        /// \param sdkConsumerCertAuthority - The user of the SDK can pass the cert authority which will be used in SSL
        ///                                   handshake. If the empty string is passed will use the default CA's
        /// \return - Unique pointer instance of the Service class.
        static std::unique_ptr<Service> Create(const std::string& url,
                                               std::string_view sdkConsumerCertAuthority = "",
                                               const std::string& clientKeyFileName = "", 
                                               const std::string& clientCertFileName = "");

        /// Add a HTTP request header.
        /// \param key - The key by which the header is known (e.g., "Accept").
        /// \param value - The value associated with it.
        void AddHeader(const std::string& key, const std::string& value);

        /// Execute a get request and on completion the callback is executed.
        /// \param ioContext - IO context object which is used by boot:asio to before OS's I/O services.
        /// \param callback - The response callback.
        void ExecuteGet(IOContext& ioContext, ServiceCallback&& callback);

        /// Execute a post request and on completion the callback is executed.
        /// \param body - The HTTP body part of the request
        /// \param ioContext - IO context object which is used by boot:asio to before OS's I/O services.
        /// \param callback - The response callback.
        void ExecutePost(std::string&& body, IOContext& ioContext, ServiceCallback&& callback);

        /// Execute a patch request and on completion the callback is executed.
        /// \param body - The HTTP body part of the request
        /// \param ioContext - IO context object which is used by boot:asio to before OS's I/O services.
        /// \param callback - The response callback.
        void ExecutePatch(std::string&& body, IOContext& ioContext, ServiceCallback&& callback);

		/// Return the host of the current service.
        /// \return - Host of the current service.
        std::string getHost() const { return m_host; }

        /// Return the target of the current service.
        /// \return - Target of the current service.
        std::string getTarget() const;

        /// Convert boost::beast::http::status to http status code.
        /// \param status - The boost::beast::http::status status.
        /// \return - An unsigned http status code.
        static unsigned GetStatus(bb::http::status status) {
            return static_cast<unsigned>(status);
        }

        /// Check if socket is secure.
        /// \return - True if secure socket false otherwise.
        bool isSSLSocket() const {
            return m_secure;
        }

        // Not supported.
        Service(const Service &) = delete;
        Service(Service &&) = delete;
        Service & operator=(const Service &) = delete;
        Service & operator=(Service &&) = delete;

    private:
        /// Constructor
        Service(std::string&& schema, std::string&& host, std::string&& port,
                std::string&& target, std::string_view sdkConsumerCertAuthority, const std::string& clientKeyFileName, 
                                               const std::string& clientCertFileName);

        // Data
        SSLContext m_sslContext {SSLContext::tlsv12_client}; // Support TLS 1.2
        HttpRequest m_request {};
        std::string m_schema;
        std::string m_host;
        bool m_secure;
    };
}  // namespace virtru::network

#endif //VIRTRU_HTTP_CLIENT_SERVICE_H
