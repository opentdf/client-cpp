/*
* Copyright 2023 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//

#ifndef VIRTRU_TDF_READER_H
#define VIRTRU_TDF_READER_H

#include "crypto/bytes.h"

namespace virtru {

    using namespace virtru::crypto;

    class ITDFReader {
    public:
        /// Destructor
        virtual ~ITDFReader() = default;

        /// Get the manifest content.
        /// \return - Return the manifest as string.
        virtual const std::string& getManifest() = 0;

        /// Read payload of length starting the index.
        /// \param index - index within data where read is to begin
        /// \param length - length of data to be retrieved starting from index
        /// \param bytes - buffer for storing the retrieved data
        virtual void readPayload(size_t index, size_t length, WriteableBytes &bytes) = 0;

        /// Get the size of the payload.
        /// \return std::uint64_t - Size of the payload.
        virtual std::uint64_t getPayloadSize() const = 0;
    };
}


#endif //VIRTRU_TDF_READER_H
