/*
* Copyright 2021 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
// Created by sujan kota on 12/8/21.
//

#ifndef VIRTRU_TDF_WRITER_H
#define VIRTRU_TDF_WRITER_H

#include "crypto/bytes.h"

namespace virtru {

    using namespace virtru::crypto;

    class TDFWriter {
    public:
        // Destructor
        virtual ~TDFWriter() = default;

        /// Set the payload size of the TDF
        /// \param payloadSize
        virtual void setPayloadSize(int64_t payloadSize) = 0;

        /// Append the manifest contents to the archive.
        /// \param manifest - Contents of the manifest file.
        /// NOTE: Manifest should be always be added at the end after writing the payload for TDF.
        /// NOTE: Manifest should be always be added before writing the payload for TDF2.
        virtual void appendManifest(std::string&& manifest) = 0;

        /// Append the manifest contents to the archive.
        /// \param payload - encrypted payload.
        virtual void appendPayload(Bytes payload) = 0;
    };
}  // namespace virtru
#endif //VIRTRU_TDF_WRITER_H
