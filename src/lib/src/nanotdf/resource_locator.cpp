/*
* Copyright 2020 Virtru Corporation
*
* SPDX - License - Identifier: MIT
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/05/27
//

#include <cstdint>
#include <regex>

#include "tdf_exception.h"
#include "utils.h"
#include "resource_locator.h"

namespace virtru::nanotdf {

    using namespace virtru::crypto;

    /// Constructor
    ResourceLocator::ResourceLocator() {}

    /// Construct resource locator object from the url
    ResourceLocator::ResourceLocator(const std::string& resourceUrl) {
        std::regex urlRegex("(http|https)://(\[^ ]*)");
        std::cmatch what;
        if(!regex_match(resourceUrl.c_str(), what, urlRegex)) {
            std::string errorMsg{"Failed to parse url, expected:'(http|https)://<domain>/<target>' actual:"};
            errorMsg.append(resourceUrl);
            ThrowException(std::move(errorMsg));
        }

        std::string protocolAsString(what[1].first, what[1].second);
        if (Utils::iequals(protocolAsString, "http")) {
            m_protocol = ResourceLocator::Protocol::HTTP;
        } else if (Utils::iequals(protocolAsString, "https")) {
            m_protocol = ResourceLocator::Protocol::HTTPS;
        } else {
            ThrowException("Unsupported protocol for resource locator");
        }

        m_bodyLength = what[2].length();
        m_body.resize(what[2].length());
        std::transform(what[2].first, what[2].second, m_body.begin(),
                       [] (char c) { return gsl::byte(c); });
    }

    /// Construct resource locator object by parsing the bytes the url.
    ResourceLocator::ResourceLocator(Bytes bytes) {

        // Read the type of the policy.
        std::uint8_t protocol;
        std::memcpy(&protocol, bytes.data(), sizeof(protocol));
        m_protocol = ResourceLocator::Protocol(protocol);
        switch(m_protocol) {
            case ResourceLocator::Protocol::HTTP:
            case ResourceLocator::Protocol::HTTPS:
                break;
            default:
                ThrowException("Unsupported protocol for resource locator");
                break;
        }
        m_protocol = ResourceLocator::Protocol(protocol);

        // Adjust the bytes.
        bytes = bytes.subspan(sizeof(protocol));

        // Read the url body length;
        std::memcpy(&m_bodyLength, bytes.data(), sizeof(m_bodyLength));

        // Adjust the bytes.
        bytes = bytes.subspan(sizeof(m_bodyLength));

        // Read the url body;
        m_body.resize(m_bodyLength);
        std::memcpy(m_body.data(), bytes.data(), m_bodyLength);
    }

    // Provide default implementation.
    ResourceLocator::~ResourceLocator()  = default;
    ResourceLocator::ResourceLocator(const ResourceLocator&) = default;
    ResourceLocator& ResourceLocator::operator=(const ResourceLocator&) = default;
    ResourceLocator::ResourceLocator(ResourceLocator&&) noexcept = default;
    ResourceLocator& ResourceLocator::operator=(ResourceLocator&&) noexcept = default;

    /// Return the resource url.
    /// \return std::string - The resource url.
    std::string ResourceLocator::getResourceUrl() const {
        std::ostringstream stringStream;

        // Append protocol
        switch(m_protocol) {
            case ResourceLocator::Protocol::HTTP:
                stringStream << "http://";
                break;
            case ResourceLocator::Protocol::HTTPS:
                stringStream << "https://";
                break;
            default:
                ThrowException("Unsupported protocol for resource locator");
                break;
        }

        // Append the body
        for (const auto& c : m_body) {
            stringStream << (char)c;
        }

        return stringStream.str();
    }

    /// Get the total size required to store ResourceLocator data.
    std::uint16_t ResourceLocator::getTotalSize() const {
        return (sizeof(Protocol) + sizeof(m_bodyLength) + m_body.size());
    }

    /// Write this object data into the buffer and return the amount of bytes
    std::uint16_t ResourceLocator::writeIntoBuffer(WriteableBytes bytes) const {

        if (bytes.size() < getTotalSize()) {
            ThrowException("Failed to write resource locator - invalid buffer size.");
        }

        std::uint16_t writeBytes = 0;

        // Write the protocol type.
        std::memcpy(bytes.data(), &m_protocol, sizeof(m_protocol));
        writeBytes += sizeof(m_protocol);

        // Write the url body length;
        std::memcpy(bytes.data() + writeBytes, &m_bodyLength, sizeof(m_bodyLength));
        writeBytes += sizeof(m_bodyLength);

        // Read the url body;
        std::memcpy(bytes.data() + writeBytes, m_body.data(), m_body.size());
        writeBytes += m_body.size();

        return writeBytes;
    }
}
