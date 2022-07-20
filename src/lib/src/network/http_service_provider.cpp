/*
* Copyright 2021 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
// Created by Sujan Reddy on 7/17/21.
//

#include <iostream>
#include "nlohmann/json.hpp"
#include <utility>

#include "logger.h"
#include "network_util.h"
#include "sdk_constants.h"
#include "http_client_service.h"
#include "utils.h"
#include "http_service_provider.h"

namespace virtru::network {

    /// Constructor
    HTTPServiceProvider::HTTPServiceProvider(HttpHeaders  headers) :
        m_httpHeaders(std::move(headers)) {}

    /// Execute a get request and on completion the callback is executed.
    void HTTPServiceProvider::executeGet(const std::string &url,
                                         const HttpHeaders &headers,
                                         HTTPServiceCallback &&callback,
                                         const std::string& sdkConsumerCertAuthority,
                                         const std::string& clientKeyFileName,
                                         const std::string& clientCertFileName) {
        auto service = Service::Create(url, sdkConsumerCertAuthority, clientKeyFileName, clientCertFileName);

        LogDebug("GET URL = \"" + url + "\"");

        // Add headers
        updateService(*service, kHttpGet, headers, {}, url);

        unsigned int status = kHTTPBadRequest;
        std::string responseBody;

        IOContext ioContext;
        service->ExecuteGet(ioContext, [&status, &responseBody](ErrorCode errorCode, HttpResponse &&response) {
            // TODO: Ignore stream truncated error. Looks like the server is not shutting down gracefully.
            // https://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
            if (errorCode && errorCode.value() != 1) { // something is wrong
                std::ostringstream oss;
                oss << "Error code:" << errorCode.value() << " " << errorCode.message();
                LogWarn(oss.str());
                responseBody = errorCode.message();
            } else {
                status = Service::GetStatus(response.result());
                responseBody = response.body();
            }

            // Not everything throws an errorCode
            if ((!errorCode) && (status != kHTTPOk)) {
                std::ostringstream oss;
                oss << "status: " << status << " " << responseBody;
                LogDebug(oss.str());
            }
        });

        // Run the context - It's blocking call until i/o operation is done.
        ioContext.run();

        // invoke the callback.
        LogDebug("HTTPServiceProvider::executeGet responseBody="+responseBody);
        callback(status, std::move(responseBody));
    }


    /// Execute a put request and on completion the callback is executed.
    void HTTPServiceProvider::executePut(const std::string &url,
                                          const HttpHeaders &headers,
                                          std::string &&body,
                                          HTTPServiceCallback &&callback,
                                          const std::string& sdkConsumerCertAuthority,
                                          const std::string& clientKeyFileName,
                                          const std::string& clientCertFileName) {

        auto service = Service::Create(url, sdkConsumerCertAuthority, clientKeyFileName, clientCertFileName);

        LogDebug("PUT URL = \"" + url + "\"");

        // Add headers
        updateService(*service, kHttpPut, headers, body, url);

        LogDebug("Body = \"" + body + "\"");

        unsigned int status = kHTTPBadRequest;
        std::string responseBody;

        IOContext ioContext;

        service->ExecutePut(std::move(body), ioContext, [&status, &responseBody](ErrorCode errorCode, HttpResponse &&response) {
            // TODO: Ignore stream truncated error. Looks like the server is not shutting down gracefully.
            // https://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
            if (errorCode && errorCode.value() != 1) { // something is wrong
                std::ostringstream os{"Error code: "};
                os << errorCode.value() << " " << errorCode.message();
                LogWarn(os.str());
                responseBody = errorCode.message();
            } else {
                status = Service::GetStatus(response.result());
                responseBody = response.body();
            }

            // Not everything throws an errorCode
            if ((!errorCode) && (status != kHTTPOk)) {

                std::ostringstream os{"status: "};
                os << status << " " << responseBody;
                LogDebug(os.str());
            }
        });

        // Run the context - It's blocking call until i/o operation is done.
        ioContext.run();

        // invoke the callback.
        LogDebug("HTTPServiceProvider::executePut responseBody="+responseBody);
        callback(status, std::move(responseBody));
    }

    /// Execute a post request and on completion the callback is executed.
    void HTTPServiceProvider::executePost(const std::string &url,
                                          const HttpHeaders &headers,
                                          std::string &&body,
                                          HTTPServiceCallback &&callback,
                                          const std::string& sdkConsumerCertAuthority,
                                          const std::string& clientKeyFileName,
                                          const std::string& clientCertFileName) {

        auto service = Service::Create(url, sdkConsumerCertAuthority, clientKeyFileName, clientCertFileName);

        LogDebug("POST URL = \"" + url + "\"");

        // Add headers
        updateService(*service, kHttpPost, headers, body, url);

        LogDebug("Body = \"" + body + "\"");

        unsigned int status = kHTTPBadRequest;
        std::string responseBody;

        IOContext ioContext;

        service->ExecutePost(std::move(body), ioContext, [&status, &responseBody](ErrorCode errorCode, HttpResponse &&response) {
            // TODO: Ignore stream truncated error. Looks like the server is not shutting down gracefully.
            // https://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
            if (errorCode && errorCode.value() != 1) { // something is wrong
                std::ostringstream os{"Error code: "};
                os << errorCode.value() << " " << errorCode.message();
                LogWarn(os.str());
                responseBody = errorCode.message();
            } else {
                status = Service::GetStatus(response.result());
                responseBody = response.body();
            }

            // Not everything throws an errorCode
            if ((!errorCode) && (status != kHTTPOk)) {

                std::ostringstream os{"status: "};
                os << status << " " << responseBody;
                LogDebug(os.str());
            }
        });

        // Run the context - It's blocking call until i/o operation is done.
        ioContext.run();

        // invoke the callback.
        LogDebug("HTTPServiceProvider::executePost responseBody="+responseBody);
        callback(status, std::move(responseBody));
    }

    /// Execute a patch request and on completion the callback is executed.
    void HTTPServiceProvider::executePatch(const std::string &url,
                                           const HttpHeaders &headers,
                                           std::string &&body,
                                           HTTPServiceCallback &&callback,
                                           const std::string& sdkConsumerCertAuthority,
                                           const std::string& clientKeyFileName,
                                           const std::string& clientCertFileName) {

        auto service = Service::Create(url, sdkConsumerCertAuthority, clientKeyFileName, clientCertFileName);

        LogDebug("PATCH URL = \"" + url + "\"");

        // Add headers
        updateService(*service, kHttpPatch, headers, body, url);

        LogDebug("Body = \"" + body + "\"");

        unsigned int status = kHTTPBadRequest;
        std::string responseBody;

        IOContext ioContext;

        service->ExecutePatch(std::move(body), ioContext, [&status, &responseBody](ErrorCode errorCode, HttpResponse &&response) {
            // TODO: Ignore stream truncated error. Looks like the server is not shutting down gracefully.
            // https://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
            if (errorCode && errorCode.value() != 1) { // something is wrong
                std::ostringstream os{"Error code: "};
                os << errorCode.value() << " " << errorCode.message();
                LogWarn(os.str());
                responseBody = errorCode.message();
            } else {
                status = Service::GetStatus(response.result());
                responseBody = response.body();
            }

            // Not everything throws an errorCode
            if ((!errorCode) && (status != kHTTPOk)) {
                std::ostringstream os{"status: "};
                os << status << " " << responseBody;
                LogDebug(os.str());
            }
        });

        // Run the context - It's blocking call until i/o operation is done.
        ioContext.run();

        // invoke the callback.
        LogDebug("HTTPServiceProvider::executePatch responseBody="+responseBody);
        callback(status, std::move(responseBody));
    }

    /// Execute a head request and on completion the callback is executed.
    void HTTPServiceProvider::executeHead(const std::string &url,
                                         const HttpHeaders &headers,
                                         HTTPServiceCallback &&callback,
                                         const std::string& sdkConsumerCertAuthority,
                                         const std::string& clientKeyFileName,
                                         const std::string& clientCertFileName) {
        auto service = Service::Create(url, sdkConsumerCertAuthority, clientKeyFileName, clientCertFileName);

        LogDebug("HEAD URL = \"" + url + "\"");

        // Add headers
        updateService(*service, kHttpHead, headers, {}, url);

        unsigned int status = kHTTPBadRequest;
        std::string responseBody;

        IOContext ioContext;
        service->ExecuteHead(ioContext, [&status, &responseBody](ErrorCode errorCode, HttpResponse &&response) {
            // TODO: Ignore stream truncated error. Looks like the server is not shutting down gracefully.
            // https://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
            if (errorCode && errorCode.value() != 1) { // something is wrong
                std::ostringstream oss;
                oss << "Error code:" << errorCode.value() << " " << errorCode.message() << "\n";
                LogError(oss.str());
                responseBody = oss.str();
            } else {
                status = Service::GetStatus(response.result());
            }

            // Return headers in response body since there is no body for a HEAD response
            for (auto &hIter: response.base()) {
                std::ostringstream oss;
                oss << hIter.name_string() << ": " << hIter.value() << "\n";
                responseBody.append(oss.str());
            }

            // Not everything throws an errorCode
            if ((!errorCode) && (status != kHTTPOk)) {
                std::ostringstream oss;
                oss << "status: " << status << " " << responseBody;
                LogDebug(oss.str());
            }
        });

        // Run the context - It's blocking call until i/o operation is done.
        ioContext.run();

        // invoke the callback.
        LogDebug("HTTPServiceProvider::executeHead responseBody="+responseBody);
        callback(status, std::move(responseBody));
    }

    /// Update the service with authorization header and other required headers
    void HTTPServiceProvider::updateService(Service &service, const std::string &/*httpVerb*/,
                                            const HttpHeaders &headers, const std::string &/*body*/,
                                            const std::string &/*url*/) {
        // NOTE: body and url are not used, avoid compiler warning by commenting out var names
        LogTrace("HTTPServiceProvider::updateService");

        // Add all the headers from the caller...from both m_httpHeaders and headers
        for (const auto &[key, value]: headers) {
            LogDebug("adding from headers " + key);
            service.AddHeader(key, value);
        }
        for (const auto &item: m_httpHeaders) {
            LogDebug("adding from m_httpHeaders " + item.first);
            service.AddHeader(item.first, item.second);
        }

        // Set content type to default if not already specified
        auto hIter = headers.find(kContentTypeKey);
        if (hIter == headers.end()) {
            LogDebug("Content type not set, defaulting to json");
            service.AddHeader(kContentTypeKey, kContentTypeJsonValue);
        } else {
            LogDebug("Content type previously set");
        }

        // Set Accept to default if not specified
        hIter = headers.find(kAcceptKey);
        if (hIter == headers.end()) {
            LogDebug("Accept not set, defaulting to json");
            service.AddHeader(kAcceptKey, kAcceptKeyValue);
        } else {
            LogDebug("Accept previously set");
        }

        // Set Host to default if not specified
        hIter = headers.find(kHostKey);
        if (hIter == headers.end()) {
            LogDebug("Host not set, adding default");
            auto host = service.getHost();
            service.AddHeader(kHostKey, host);
        } else {
            LogDebug("Host previously set");
        }

        // Set Host to default if not specified
        hIter = headers.find(kDateKey);
        if (hIter == headers.end()) {
            LogDebug("Date not set, adding default");
            std::string date = nowRfc1123();
            service.AddHeader(kDateKey, date);
        } else {
            LogDebug("Date previously set");
        }
    }
}
