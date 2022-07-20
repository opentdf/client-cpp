/*
* Copyright 2022 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//

#ifndef VIRTRU_TDF_ARCHIVE_WRITER_V2_H
#define VIRTRU_TDF_ARCHIVE_WRITER_V2_H


#include <string>
#include <memory>
#include <vector>

#include "crypto/bytes.h"
#include "io_provider.h"
#include "logger.h"
#include "tdf_constants.h"
#include "zipmanager/zip_headers.h"

namespace virtru {

    using namespace virtru::crypto;

    class ITDFWriter {
    public:
        // Destructor
        virtual ~ITDFWriter() = default;

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

        /// Finalize archive entry.
        virtual void finish() = 0;
    };


    class TDFArchiveWriter: public ITDFWriter{
    public:

        /// Constructor for TDFArchiveWriter
        /// \param outputProvider - The zip data will write to the output provider.
        /// \param manifestFilename - A manifest file name to be used in the TDF file (manifest.xml - TDF2,
        ///                           manifest.json - TDF).
        /// \param payloadFileName - A payload file name to be used in the TDF file
        TDFArchiveWriter(IOutputProvider* outputProvider,
                         std::string manifestFilename,
                         std::string payloadFilename);

        /// Delete default constructor
        TDFArchiveWriter() = delete;

        /// Destructor
        ~TDFArchiveWriter() = default;


        /// Append the manifest contents to the archive.
        /// \param payload - encrypted payload.
        template <typename Payload,typename = ExplicitlyConvertibleToBytes <Payload>>
        void appendPayload(const Payload & payload) {
            LogTrace("TDFArchiveWriter::appendPayload");
            appendPayload( crypto::toDynamicBytes(payload));
        }

        /// Not supported.
        TDFArchiveWriter(const TDFArchiveWriter &) = delete;
        TDFArchiveWriter(TDFArchiveWriter &&) = delete;
        TDFArchiveWriter & operator=(const TDFArchiveWriter &) = delete;
        TDFArchiveWriter & operator=(TDFArchiveWriter &&) = delete;

    public: // From ITDFWriter
        /// Set the payload size of the TDF
        /// \param payloadSize
        void setPayloadSize(int64_t payloadSize) override { LogTrace("TDFArchiveWriter::appendPayload"); m_payloadSize = payloadSize; }

        /// Append the manifest contents to the archive.
        /// \param manifest - Contents of the manifest file.
        /// NOTE: Manifest should be always be added at the end after writing the payload for TDF.
        /// NOTE: Manifest should be always be added before writing the payload for TDF2.
        void appendManifest(std::string&& manifest) override;

        /// Append the manifest contents to the archive.
        /// \param payload - encrypted payload.
        void appendPayload(Bytes payload) override;

        /// Finalize archive entry.
        void finish() override;


    private:
        /// Write archive central directory.
        void writeCentralDirectory();

        /// Write archive end of central directory.
        void writeEndOfCentralDirectory();

        /// Write archive end of central directory for zip64.
        void writeZip64EndOfCentralDirectory();

        /// Write archive end of central directory locator for zip64.
        void writeZip64EndOfCentralDirectoryLocator();


    private: /// Data

        struct FileInfo
        {
            //uint32_t crc;
            uint64_t size;
            uint64_t offset;
            std::string fileName;
        };

        enum class PayloadState {
            Initial,
            Appending,
            Finished,
            Failed,
        };


        IOutputProvider*        m_outputProvider;
        std::string             m_manifestFilename;
        std::string             m_payloadFilename;
        uint64_t                m_payloadSize {0};
        uint64_t                m_currentOffset {0};
        uint64_t                m_lastOffsetCDFH {0};
        bool                    m_isZip64 {false};
        std::vector<FileInfo>   m_fileInfo;
        PayloadState            m_payloadState {PayloadState::Initial};


    };
} // namespace virtru

#endif //VIRTRU_TDF_ARCHIVE_WRITER_V2_H
