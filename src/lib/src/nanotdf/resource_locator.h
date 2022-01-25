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

#ifndef VIRTRU_RESOURCE_LOCATOR_H
#define VIRTRU_RESOURCE_LOCATOR_H

#include <vector>

#include "crypto/crypto_utils.h"

namespace virtru::nanotdf {

    using namespace virtru::crypto;

    /*********************** Resource Locator**************************
    |The Resource Locator is a way for the nano tdf to represent references to
    |external resources in as succinct a format as possible.
    |
    | Section       | Minimum Length (B)  | Maximum Length (B)  |
    |---------------|---------------------|---------------------|
    | Protocol Enum | 1                   | 1                   |
    | Body Length   | 1                   | 1                   |
    | Body          | 1                   | 255                 |
    *********************** Resource Locator**************************/

    class ResourceLocator {
    public:
        // Protocol supported by nano tdf.
        enum class Protocol : std::uint8_t {
            HTTP = 0x00,
            HTTPS = 0x01
        };

    public:
        /// Constructor
        ResourceLocator();

        /// Construct resource locator object from the url
        /// \param resourceUrl - The resource url.
        explicit ResourceLocator(const std::string& resourceUrl);

        /// Construct resource locator object by parsing the bytes the url
        /// \param bytest - The bytes containing the information of the resource locator.
        explicit ResourceLocator(Bytes bytes);

        /// Destructors
        ~ResourceLocator();

        /// Copy constructor
        ResourceLocator(const ResourceLocator& resourceLocator);

        /// Assignment operator
        ResourceLocator& operator=(const ResourceLocator& resourceLocator);

        /// Move copy constructor
        ResourceLocator(ResourceLocator&& resourceLocator) noexcept;

        /// Move assignment operator
        ResourceLocator& operator=(ResourceLocator&& resourceLocator) noexcept;

    public:
        /// Return the resource url.
        /// \return The resource url.
        std::string getResourceUrl()  const;

        /// Get the total size required to store ResourceLocator data.
        /// \return Return the total size required to store ResourceLocator data.
        std::uint16_t getTotalSize() const ;

        /// Write this object data into the buffer and return the amount of bytes
        /// added to the buffer.
        /// \param bytes - The buffer
        /// \return The amount of bytes added to the buffer.
        std::uint16_t writeIntoBuffer(WriteableBytes bytes) const;

    private: /// Data
        Protocol                 m_protocol{ResourceLocator::Protocol::HTTPS};
        std::uint8_t             m_bodyLength{0};
        std::vector<gsl::byte>   m_body;
    };
}

#endif //VIRTRU_RESOURCE_LOCATOR_H

