/*
* Copyright 2021 Virtru Corporation
*
* SPDX - License - Identifier: MIT
*
*/
//
// Created by sujan kota on 12/7/21.
//

#ifndef VIRTRU_TDF_READER_H
#define VIRTRU_TDF_READER_H

#include "crypto/bytes.h"

namespace virtru {

    using namespace virtru::crypto;

    class TDFReader {
    public:
        // Destructor
        virtual ~TDFReader() = default;

        /// Get the manifest content.
        /// \return - Return the manifest as string.
        virtual const std::string& getManifest() = 0;

        /// Read the payload contents into the buffer.
        /// The size of buffer could be less than requested size.
        /// \param buffer - WriteableBytes
        virtual void readPayload(WriteableBytes& buffer) = 0;

        /// Get the size of the payload.
        /// \return std::uint64_t - Size of the payload.
        virtual std::int64_t getPayloadSize() const = 0;
    };
}  // namespace virtru

#endif //VIRTRU_TDF_READER_H
