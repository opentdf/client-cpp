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

#ifndef VIRTRU_TDF_WRITER_H
#define VIRTRU_TDF_WRITER_H

#include "crypto/bytes.h"
#include "manifest_data_model.h"

namespace virtru {

    using namespace virtru::crypto;

    class ITDFWriter {
    public:
        // Destructor
        virtual ~ITDFWriter() = default;

        /// Set the payload size of the TDF
        /// \param payloadSize
        virtual void setPayloadSize(int64_t payloadSize) = 0;

        /// Append the manifest contents to the output source.
        /// \param manifestDataModel - Data model containing the manifest data.
        virtual void appendManifest(ManifestDataModel manifestDataModel) = 0;

        /// Append the payload contents to the output source.
        /// \param payload - encrypted payload.
        virtual void appendPayload(Bytes payload) = 0;

        /// Finalize archive entry.
        virtual void finish() = 0;
    };

} // namespace virtru

#endif //VIRTRU_TDF_WRITER_H
