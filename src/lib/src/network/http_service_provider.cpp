/*
* Copyright 2021 Virtru Corporation
*
* SPDX - License - Identifier: MIT
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
            // TODO: Ignore stream truncated error. Looks like the server is not shuting downn gracefully.
            // https://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
            if (errorCode && errorCode.value() != 1) { // something is wrong
                std::ostringstream os{"Error code: "};
                os << errorCode.value() << " " << errorCode.message();
                LogError(os.str());
            }

            status = Service::GetStatus(response.result());

            responseBody = response.body();

            // Not everything throws an errorCode
            if ((!errorCode) && (status != kHTTPOk)) {
                std::ostringstream os{"status: "};
                os << status << " " << responseBody;
                LogError(os.str());
            }
        });

        // Run the context - It's blocking call until i/o operation is done.
        ioContext.run();

        // invoke the callback.
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
            // TODO: Ignore stream truncated error. Looks like the server is not shuting downn gracefully.
            // https://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
            if (errorCode && errorCode.value() != 1) { // something is wrong
                std::ostringstream os{"Error code: "};
                os << errorCode.value() << " " << errorCode.message();
                LogError(os.str());
            }

            status = Service::GetStatus(response.result());
            responseBody = response.body();

            // Not everything throws an errorCode
            if ((!errorCode) && (status != kHTTPOk)) {
                std::ostringstream os{"status: "};
                os << status << " " << responseBody;
                LogError(os.str());
            }
        });

        // Run the context - It's blocking call until i/o operation is done.
        ioContext.run();

        // invoke the callback.
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
            // TODO: Ignore stream truncated error. Looks like the server is not shuting downn gracefully.
            // https://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
            if (errorCode && errorCode.value() != 1) { // something is wrong
                std::ostringstream os{"Error code: "};
                os << errorCode.value() << " " << errorCode.message();
                LogError(os.str());
            }

            status = Service::GetStatus(response.result());
            responseBody = response.body();

            // Not everything throws an errorCode
            if ((!errorCode) && (status != kHTTPOk)) {
                std::ostringstream os{"status: "};
                os << status << " " << responseBody;
                LogError(os.str());
            }
        });

        // Run the context - It's blocking call until i/o operation is done.
        ioContext.run();

        // invoke the callback.
        callback(status, std::move(responseBody));
    }

    /// Update the service with authorization header and other required headers
    void HTTPServiceProvider::updateService(Service &service, const std::string &httpVerb,
                                            const HttpHeaders &headers, const std::string &/*body*/,
                                            const std::string &/*url*/) {
        // NOTE: body and url are not used, avoid compiler warning by commenting out var names
        bool bIsHttpGet = (httpVerb == kHttpGet);

        // Add all the headers from the caller.
        for (const auto &[key, value] : headers) {
            service.AddHeader(key, value);
        }

        //DON'T whack content type if caller already set it - for instance
        //if they're using POST with `x-www-form-urlencoded` don't force JSON
        auto hIter = headers.find(kContentTypeKey);

        if (hIter == headers.end()) {
            LogDebug("POST content type not set, defaulting to application/json");
            std::string contentTypeValue = kContentTypeJsonValue;
            //No content-type if GET
            if (!bIsHttpGet) {
                service.AddHeader(kContentTypeKey, contentTypeValue);
            }
        } else {
            LogDebug("POST content type previously set");
        }

        // Add 'Accept' as json.
        service.AddHeader(kAcceptKey, kAcceptKeyValue);

        // Add 'Host' header
        auto host = service.getHost();
        service.AddHeader(kHostKey, host);

        // Add 'Date' header
        std::string date = nowRfc1123();
        service.AddHeader(kDateKey, date);

        // Supply null headers as default - none are required
        std::map<std::string, std::string> noHeaders;
        auto target = service.getTarget();

        for (const auto& item : m_httpHeaders) {
            LogDebug("adding " + item.first);
            service.AddHeader(item.first, item.second);
        }
    }
}
