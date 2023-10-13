/*
* Copyright 2020 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/04/17
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

namespace virtru {

    constexpr auto kEntityUrlPath = "/v1/entity_object";

    using namespace virtru::network;

    /// Get KAS pubkey from KAS endpoint.
    std::string Utils::getKasPubkeyFromURLsp(const std::string &kasGetPublicKeyUrl, 
                                             std::weak_ptr<INetwork> httpServiceProvider,
                                             const std::string &sdkConsumerCertAuthority,
                                             const std::string &clientKeyFileName,
                                             const std::string &clientCertFileName) {

        std::string kasPubKeyString;
        unsigned status = kHTTPBadRequest;
        std::promise<void> netPromise;
        auto netFuture = netPromise.get_future();

        LogTrace("Utils::getKasPubkeyFromURL(url, serviceProvider)");
        if (auto sp = httpServiceProvider.lock()) { // Rely on callback interface
            sp->executeGet(
                kasGetPublicKeyUrl, {},
                [&netPromise, &kasPubKeyString, &status](
                        unsigned int statusCode, std::string &&response) {
                    status = statusCode;
                    kasPubKeyString = response;
                    netPromise.set_value();
                },
                sdkConsumerCertAuthority,
                clientKeyFileName,
                clientCertFileName);
        } else {
            ThrowException("Unable to lock network provider", VIRTRU_NETWORK_ERROR);
        }

        netFuture.get();

        // Handle HTTP error.
        if (!Utils::goodHttpStatus(status)) {
            std::string exceptionMsg = "Get kas public key failed status:";
            exceptionMsg += std::to_string(status);
            exceptionMsg += " - ";
            exceptionMsg += kasPubKeyString;
            ThrowException(std::move(exceptionMsg), VIRTRU_NETWORK_ERROR);
        }

        //Verify that fetched data is kas public key.
        if (kasPubKeyString.rfind("\"-----BEGIN CERTIFICATE-----", 0) != 0){
            ThrowException("Get kas public key failed, kas public key is: "+kasPubKeyString, VIRTRU_NETWORK_ERROR);
        }

        LogDebug(kasPubKeyString);
        kasPubKeyString.erase(0, 1);
        kasPubKeyString.erase(kasPubKeyString.size() - 2);

        boost::replace_all(kasPubKeyString, "\\n", "\n");

        LogDebug("Fetched default KAS public key: " + kasPubKeyString);
        //TODO as per JS code, consider handling KAS endpoints that don't present proper PEM-encoded public keys
        //Why on earth a KAS endpoint named `kas_public_key` would return anything other than a PEM-encoded public key
        //is beyond me - would consider it a KAS bug if that's an actual scenario.
        // auto kasPubKey = extractPemFromKasKeyString(kasPubKeyString);

        return kasPubKeyString;
    }

    /// Wrapper for above with service create for callers that do not provide one
    std::string Utils::getKasPubkeyFromURL(const std::string &kasGetPublicKeyUrl) {
        LogTrace("Utils::getKasPubkeyFromURL(url)");

        HttpHeaders headers;
        std::shared_ptr<HTTPServiceProvider> serviceProvider = std::make_shared<HTTPServiceProvider>(headers);

        return Utils::getKasPubkeyFromURLsp(kasGetPublicKeyUrl, serviceProvider);
    }

    /// Get the entity object from eas.
    EntityObject Utils::getEntityObject(const std::string &easUrl,
                                        const std::string &sdkConsumerCertAuthority,
                                        const std::string &clientKeyFileName,
                                        const std::string &clientCertFileName,
                                        const std::unordered_map<std::string, std::string> &headers,
                                        std::string body) {

        auto entityObjectUrl = easUrl + kEntityUrlPath;
        auto service = Service::Create(entityObjectUrl, sdkConsumerCertAuthority, clientKeyFileName, clientCertFileName);

        // Add the headers.
        for (const auto &[key, value] : headers) {
            service->AddHeader(key, value);
        }

        // Add the host to the header, may want to push this to upper layer.
        service->AddHeader(kHostKey, service->getHost());

        std::string entityObjectJson;

        IOContext ioContext;
        service->ExecutePost(std::move(body), ioContext,
                             [&entityObjectJson](ErrorCode errorCode, HttpResponse &&response) {
                                 // TODO: Ignore stream truncated error. Looks like the server is not shuting downn gracefully.
                                 // https://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
                                 if (errorCode && errorCode.value() != 1) { // something is wrong
                                     std::ostringstream os{"Error code: "};
                                     os << errorCode.value() << " " << errorCode.message();

                                     // Ignore for now.
                                     //std::cerr << os.str() << std::endl;
                                 }

                                 //Process low level asio network errors
                                 if (errorCode && errorCode.category() == boost::asio::error::netdb_category)
                                     throw std::runtime_error{"Network error code is "s + std::to_string(errorCode.value()) + " (" + errorCode.category().name() + ")"
                                                                                                                                                                   ". " +
                                                              errorCode.message() + ". Possibly bad EAS URL."};

                                 // TODO: Enable if verbose logging is required.
                                 //std::cout << "api/entityobject Response: " << response.body().data() << std::endl;
                                 if (response.result_int() < 200 || response.result_int() >= 300)
                                     throw std::runtime_error{"Response code is "s + std::to_string(response.result_int()) + ". Reason: " + std::string(response.reason()) + ". Possibly bad EAS URL."};

                                 entityObjectJson = response.body().data();
                             });

        // Run the context - It's blocking call until i/o operation is done.
        ioContext.run();

        // If there's no json returned, there's no point in trying to parse it
        if (entityObjectJson.size() == 0) {
          ThrowException("Failed to retrieve entity object from EAS, possibly a bad EAS URL.", VIRTRU_NETWORK_ERROR);
        }

        auto entityObject = EntityObject::createEntityObjectFromJson(entityObjectJson);
        return entityObject;
    }

    /// Compare to two strings for equality(NOTE: only ascii)
    bool Utils::iequals(const std::string &str1, const std::string &str2) {
        return std::equal(str1.begin(), str1.end(),
                          str2.begin(), str2.end(),
                          [](char a, char b) {
                              return tolower(a) == tolower(b);
                          });
    }

    /// Check for the Endianness and return true if it's little-endian
    /// \return True if it's little-endian
    bool Utils::isRunningOnLittleEndian() {

        // NOTE: Once we upgrade our compile use C++ 20 construct - std::endian

        const int value{0x01};
        const void *addressOfValue = static_cast<const void *>(&value);
        const auto *leastSignificantAddress = static_cast<const unsigned char *>(addressOfValue);
        return (*leastSignificantAddress == 0x01);
    }

    /// Apparently Boost/C++ don't have off the shelf versions of
    /// a basic url encode helper func. Oh well.
    std::string Utils::urlEncode(const std::string &str) {
        constexpr std::array<char, 16> hexChars = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

        std::string result;

        for (auto i = str.begin(); i != str.end(); ++i) {
            const std::uint8_t cp = *i & 0xFF;

            if ((cp >= 0x30 && cp <= 0x39) ||           // 0-9
                (cp >= 0x41 && cp <= 0x5A) ||           // A-Z
                (cp >= 0x61 && cp <= 0x7A) ||           // a-z
                cp == 0x2D || cp == 0x2E || cp == 0x5F) // - . _
                result += static_cast<char>(cp);
            else if (cp <= 0x7F) // length = 1
                result += std::string("%") + hexChars[(*i & 0xF0) >> 4] + hexChars[*i & 0x0F];
            else if ((cp >> 5) == 0x06) // length = 2
            {
                result += std::string("%") + hexChars[(*i & 0xF0) >> 4] + hexChars[*i & 0x0F];
                if (++i == str.end())
                    break;
                result += std::string("%") + hexChars[(*i & 0xF0) >> 4] + hexChars[*i & 0x0F];
            } else if ((cp >> 4) == 0x0E) // length = 3
            {
                result += std::string("%") + hexChars[(*i & 0xF0) >> 4] + hexChars[*i & 0x0F];
                if (++i == str.end())
                    break;
                result += std::string("%") + hexChars[(*i & 0xF0) >> 4] + hexChars[*i & 0x0F];
                if (++i == str.end())
                    break;
                result += std::string("%") + hexChars[(*i & 0xF0) >> 4] + hexChars[*i & 0x0F];
            } else if ((cp >> 3) == 0x1E) // length = 4
            {
                result += std::string("%") + hexChars[(*i & 0xF0) >> 4] + hexChars[*i & 0x0F];
                if (++i == str.end())
                    break;
                result += std::string("%") + hexChars[(*i & 0xF0) >> 4] + hexChars[*i & 0x0F];
                if (++i == str.end())
                    break;
                result += std::string("%") + hexChars[(*i & 0xF0) >> 4] + hexChars[*i & 0x0F];
                if (++i == str.end())
                    break;
                result += std::string("%") + hexChars[(*i & 0xF0) >> 4] + hexChars[*i & 0x0F];
            }
        }

        return result;
    }

    // Check HTTP status code is ok
    bool Utils::goodHttpStatus(const unsigned status) {
        bool retval = false;

        if (status >= kHTTPOk && status <= 299) {
            retval = true;
        }

        return retval;
    }

    // Get useragentvalue for header
    std::string Utils::getUserAgentValuePostFix() {
        return "Openstack C++ SDK v" + std::to_string(opentdf_VERSION_MAJOR) + "." + std::to_string(opentdf_VERSION_MINOR);
    }

    // Get client value for header
    std::string Utils::getClientValue() {
        return std::string("openstack-cpp-sdk:") + opentdf_VERSION;
    }

    /// Parse the headers from the string
    std::map<std::string, std::string> Utils::parseHeaders(const std::string& headersStr) {
        std::map<std::string, std::string> httpHeaders;

        std::istringstream resp(headersStr);
        std::string header;
        std::string::size_type index;
        while (std::getline(resp, header) && header != "\r") {
            index = header.find(':', 0);
            if(index != std::string::npos) {
                httpHeaders.insert(std::make_pair(
                        boost::algorithm::trim_copy(header.substr(0, index)),
                        boost::algorithm::trim_copy(header.substr(index + 1))
                ));
            }
        }

        return httpHeaders;
    }

    /// Parse the parameters from the string
    std::map<std::string, std::string> Utils::parseParams(std::string query) {
        std::map<std::string, std::string> params;
        size_t curStart = 0;
        do {
            size_t delimIndex = query.find('&', curStart);
            size_t equalIndex = query.find('=', curStart);
            std::string newParam = query.substr(curStart, equalIndex - curStart);
            std::string newValue = query.substr(equalIndex + 1, delimIndex - equalIndex - 1);

            params[newParam] = newValue;
            curStart = delimIndex + 1;
        } while (curStart != 0);

        return params;
    }

} // namespace virtru
