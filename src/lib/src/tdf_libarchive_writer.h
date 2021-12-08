//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/24
//  Copyright 2019 Virtru Corporation
//

#ifndef VIRTRU_TDF_ARCHIVE_WRITER_H
#define VIRTRU_TDF_ARCHIVE_WRITER_H

#include <archive.h>
#include <archive_entry.h>
#include <string>
#include <memory>

#include "tdf_constants.h"
#include "crypto/bytes.h"

namespace virtru {

    using namespace virtru::crypto;

    /// Callbacks
    using DataSourceCb = std::function< Bytes(Status&)>;
    using DataSinkCb = std::function< Status(Bytes)>;

    /// This class is a wrapper around libarchive which provides a mechanism
    /// to archive the stream of data and invokes a callback after compression is done
    ///
    /// NOTE: Requires a few changes like passing the TDF type to order the manifest append operation.
    class TDFArchiveWriter {
    public:

        /// Constructor for TDFArchiveWriter
        /// \param sinkCb - A sink callback so the user of this object can stream the compressed data anywhere.
        /// \param manifestFilename - A manifest file name to be used in the TDF file (manifest.xml - TDF2,
        ///                           manifest.json - TDF).
        /// \param payloadFileName - A payload file name to be used in the TDF file
        /// \param payloadSize - Payload size.
        TDFArchiveWriter(DataSinkCb&& sinkCb, std::string manifestFilename,
                         std::string payloadFileName, int64_t payloadSize);

        /// Delete default constructor
        TDFArchiveWriter() = delete;

        /// Destructor
        ~TDFArchiveWriter() = default;

        /// Append the manifest contents to the archive.
        /// \param manifest - Contents of the manifest file.
        /// NOTE: Manifest should be always be added at the end after writing the payload for TDF.
        /// NOTE: Manifest should be always be added before writing the payload for TDF2.
        void appendManifest(std::string&& manifest);

        /// Append the manifest contents to the archive.
        /// \param payload - encrypted payload.
        void appendPayload(Bytes payload);
        template <typename Payload,typename = ExplicitlyConvertibleToBytes <Payload>>
        void appendPayload(const Payload & payload) {
            appendPayload( crypto::toDynamicBytes(payload));
        }

        /// Finish the write operation.
        void finish();

        /// Not supported.
        TDFArchiveWriter(const TDFArchiveWriter &) = delete;
        TDFArchiveWriter(TDFArchiveWriter &&) = delete;
        TDFArchiveWriter & operator=(const TDFArchiveWriter &) = delete;
        TDFArchiveWriter & operator=(TDFArchiveWriter &&) = delete;

    private: /// static
        /// Libarchive callback after the archive operation is complete.
        /// \param writerInstance - An instance of the TDFArchiveWriter.
        /// \param buffer - A archive buffer.
        /// \param length - Length of the archive buffer.
        /// \return - Total bytes that are consumed.
        static la_ssize_t writeCallback(archive*, void* writerInstance, const void* buffer, size_t length);

    private: /// Data

        struct ArchiveDeleter { void operator()(archive* arc) {::archive_write_free(arc);} };
        using ArchiveFreePtr = std::unique_ptr<archive, ArchiveDeleter>;

        struct ArchiveEntryDeleter { void operator()(archive_entry* entry) {::archive_entry_free(entry);} };
        using ArchiveEntryFreePtr = std::unique_ptr<archive_entry, ArchiveEntryDeleter>;

        enum class PayloadState {
            Initial,
            Appending,
            Finished,
            Failed,
        };

        DataSinkCb          m_sink;
        std::string         m_manifestFilename;
        std::string         m_payloadFileName;
        int64_t             m_payloadSize;
        ArchiveFreePtr      m_archive;
        PayloadState        m_payloadState {PayloadState::Initial};
    };
} // namespace virtru

#endif //VIRTRU_TDF_ARCHIVE_WRITER_H
