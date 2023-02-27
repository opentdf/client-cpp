/*
* Copyright 2021 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
// Created by Sujan Reddy on 12/2/22.
//

#include <algorithm>
#include <iostream>
#include "nlohmann/json.hpp"

#include "logger.h"
#include "network/http_client_service.h"
#include "sdk_constants.h"
#include "tdf_exception.h"
#include "utils.h"
#include "version.h"
#include <boost/algorithm/string.hpp>
#include "oidc_configuration.h"
#include <regex>

namespace virtru {

    using namespace virtru::network;

    // Constructor
    OIDCConfiguration::OIDCConfiguration(const std::string& oidcConfigUrl) : m_oidcConfigUrl{oidcConfigUrl} {

        std::string oidcConfiguration;
        HttpHeaders headers;
        std::shared_ptr<HTTPServiceProvider> sp = std::make_shared<HTTPServiceProvider>(headers);

        unsigned status = kHTTPBadRequest;
        std::promise<void> netPromise;
        auto netFuture = netPromise.get_future();

        sp->executeGet(m_oidcConfigUrl, {}, [&netPromise, &status, &oidcConfiguration](unsigned int statusCode, std::string &&response) {
                status = statusCode;
                oidcConfiguration = response;
                netPromise.set_value();
            }, "", "", "");

        netFuture.get();

        // Handle HTTP error.
        if (!Utils::goodHttpStatus(status)) {
            std::string exceptionMsg = "Get openid configuration failed status:";
            exceptionMsg += std::to_string(status);
            exceptionMsg += " - ";
            exceptionMsg += oidcConfiguration;
            ThrowException(std::move(exceptionMsg), VIRTRU_NETWORK_ERROR);
        }

        m_configuration = oidcConfiguration;
    }

    std::string OIDCConfiguration::getOIDCUrl() const {

        auto configuration = nlohmann::json::parse(m_configuration);
        if (!configuration.contains(kTokenEndpoint)) {
            std::string exceptionMsg = "OIDC token_endpoint not found in open-id configuration";
            ThrowException(std::move(exceptionMsg), VIRTRU_NETWORK_ERROR);
        }

        std::string tokenEndpointUrl = configuration[kTokenEndpoint];

        std::regex urlRegex("(http|https):\\/\\/([^\\/ :]+):?([^\\/ ]*)(\\/?[^ ]*)");
        std::cmatch what;
        if(!regex_match(tokenEndpointUrl.c_str(), what, urlRegex)) {
            std::string errorMsg{"Failed to parse url, expected:'(http|https)//<domain>/<target>' actual:"};
            errorMsg.append(tokenEndpointUrl);
            ThrowException(std::move(errorMsg));
        }
        auto target = std::string(what[4].first, what[4].second);

        if(!regex_match(m_oidcConfigUrl.c_str(), what, urlRegex)) {
            std::string errorMsg{"Failed to parse url, expected:'(http|https)//<domain>/<target>' actual:"};
            errorMsg.append(m_oidcConfigUrl);
            ThrowException(std::move(errorMsg));
        }

        std::ostringstream oidcEndpoint;
        oidcEndpoint << std::string(what[1].first, what[1].second);
        oidcEndpoint << "://" << std::string(what[2].first, what[2].second);

        auto port = std::string(what[3].first, what[3].second);
        if (!port.empty()) {
            oidcEndpoint << ":" << port;
        }

        auto tokenEndpoint = oidcEndpoint.str() + target;
        return tokenEndpoint;
    }
}
