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

#ifndef VIRTRU_TDF_UTILS_H
#define VIRTRU_TDF_UTILS_H

#include <entity_object.h>
#include <string>
#include <unordered_map>
#include "network/http_service_provider.h"

namespace virtru {
    class Utils {
      public:
        /// Get the KAS public key from the KAS well-known HTTP endpoint
        /// \param kasGetPublicKeyUrl - The url for kas to supply its public key
        static std::string getKasPubkeyFromURL(const std::string &kasGetPublicKeyUrl);

        /// Get the KAS public key from the KAS well-known HTTP endpoint
        /// \param kasGetPublicKeyUrl - The url for kas to supply its public key
        /// \param httpServiceProvider - The network service to use for contacting kas
        /// \param sdkConsumerCertAuthority - The cert authority file.
        /// \param clientKeyFileName - The filename for the client key
        /// \param clientCertFileName - The filename for the client certificate
        static std::string getKasPubkeyFromURLsp(const std::string &kasGetPublicKeyUrl, 
                                                 std::weak_ptr<INetwork> httpServiceProvider,
                                                 const std::string &sdkConsumerCertAuthority = "",
                                                 const std::string &clientKeyFileName = "",
                                                 const std::string &clientCertFileName = "");

        /// Get the entity object from eas.
        /// \param easUrl - The eas url.
        /// \param sdkConsumerCertAuthority - The cert authority file.
        /// \param clientKeyFileName - The filename for the client key
        /// \param clientCertFileName - The filename for the client certificate
        /// \param headers - The HTTP headers that will used for getting the entity object.
        /// \param body - The POST for getting the entity object.
        /// \return The entity object.
        static EntityObject getEntityObject(const std::string &easUrl,
                                            const std::string &sdkConsumerCertAuthority,
                                            const std::string &clientKeyFileName,
                                            const std::string &clientCertFileName,
                                            const std::unordered_map<std::string, std::string> &headers,
                                            std::string body);

        /// Compare to two strings for equality(NOTE: only ascii)
        /// \param str1 - First string to compare.
        /// \param str2 - Second string to compare.
        /// \return Return true if both strings are lexicographically equal.
        static bool iequals(const std::string &str1, const std::string &str2);

        /// Check for the Endianness and return true if it's little-endian
        /// \return True if it's little-endian
        static bool isRunningOnLittleEndian();

        /// Encode a string to percent-encoded URL-safe format
        /// (RFC2396) - feel free to replace this with a standardized library
        /// \param str - The string to escape
        /// \return std::string - A new, RFC2396 encoded string
        static std::string urlEncode(const std::string &str);

        /// Check if the HTTP status code is ok
        /// \param status - The HTTP status code
        /// \return bool - True if the status is ok.
        static bool goodHttpStatus(const unsigned status);

        /// Get value of UserAgentValuePostFix
        /// \return std::string - A string with SDK version major and minor
        static std::string getUserAgentValuePostFix();

        /// Get value of clientValue
        /// \return std::string - A string describing SDK client with version
        static std::string getClientValue();

        /// Parse the headers from the string
        /// \param headers - The string with headers
        /// \return Map with HTTP headers values
        static std::map<std::string, std::string> parseHeaders(const std::string& headers);

        /// Parse the parameters from the string
        /// \param query - The string with url params
        /// \return Map with param key and values
        static std::map<std::string, std::string> parseParams(std::string query);
    };
} // namespace virtru

#endif // VIRTRU_TDF_UTILS_H
