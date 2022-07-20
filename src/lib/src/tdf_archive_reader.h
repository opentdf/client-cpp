/*
* Copyright 2022 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2022/05/16
//

#ifndef VIRTRU_TDF_ARCHIVE_READER_H
#define VIRTRU_TDF_ARCHIVE_READER_H

#include <string>
#include "io_provider.h"
#include "crypto/bytes.h"
#include "zipmanager/zip_headers.h"

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

    class TDFArchiveReader : public ITDFReader {
    public:

        /// Constructor
        /// \param IInputProvider - A input provider which hold the zip data.
        /// \param manifestFilename - A manifest file name to be used in the TDF file (manifest.xml - TDF2,
        ///                           manifest.json - TDF).
        /// \param payloadFileName - A payload file name to be used in the TDF file
        TDFArchiveReader(IInputProvider* inputProvider ,
                         const std::string& manifestFilename,
                         const std::string& payloadFileName);

        /// Delete default constructor
        TDFArchiveReader() = delete;

        /// Destructor
        ~TDFArchiveReader() override = default;

        /// Not supported.
        TDFArchiveReader(const TDFArchiveReader &) = delete;
        TDFArchiveReader(TDFArchiveReader &&) = delete;
        TDFArchiveReader & operator=(const TDFArchiveReader &) = delete;
        TDFArchiveReader & operator=(TDFArchiveReader &&) = delete;

    public: // From ITDFReader
        /// Get the manifest content.
        /// \return - Return the manifest as string.
        const std::string& getManifest() override { return m_manifest; };

        /// Read payload of length starting the index.
        /// \param index - index within data where read is to begin
        /// \param length - length of data to be retrieved starting from index
        /// \param bytes - buffer for storing the retrieved data
        void readPayload(size_t index, size_t length, WriteableBytes &bytes) override;

        /// Get the size of the payload.
        /// \return std::uint64_t - Size of the payload.
        std::uint64_t getPayloadSize() const override { return m_payloadSize; };

    public:
        void parseZipArchive();

        ///
        /// \param offset
        /// \param lengthOfManifest
        void parseFileHeaderForManifest(uint64_t offset, uint64_t lengthOfManifest);

        ///
        /// \param offset
        /// \param lengthOfPayload
        void parseFileHeaderForPayload(uint64_t offset, uint64_t lengthOfPayload);

    private: /// Data
        IInputProvider*                     m_inputProvider;
        std::string                         m_manifest;
        std::string                         m_manifestFilename;
        std::string                         m_payloadFilename;
        std::uint64_t                       m_payloadSize;
        std::uint64_t                       m_payloadStartIndex;
    };
}
#endif //VIRTRU_TDF_ARCHIVE_READER_H
