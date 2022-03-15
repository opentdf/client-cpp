/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/25
//

#ifndef VIRTRU_TDF_ARCHIVE_READER_H
#define VIRTRU_TDF_ARCHIVE_READER_H

#include <ostream>
#include <vector>
#include <archive.h>
#include <archive_entry.h>
#include <string>
#include <memory>

#include "tdf_reader.h"
#include "crypto/bytes.h"


namespace virtru {

    using namespace virtru::crypto;

    struct ArchiveReadDeleter { void operator()(archive* arc) {::archive_read_free(arc);} };
    using ArchiveReadFreePtr = std::unique_ptr<archive, ArchiveReadDeleter>;

    /// This class is a wrapper around libarchive which provides a mechanism
    /// to unarchive the stream of data.
    ///
    /// NOTE: Requires a few changes like passing the TDF type to order the manifest append operation.
    class TDFArchiveReader : public TDFReader {
    public:

        /// Constructor for TDFArchiveReader
        /// \param inStream - A source input stream which hold the zip data.
        /// \param manifestFilename - A manifest file name to be used in the TDF file (manifest.xml - TDF2,
        ///                           manifest.json - TDF).
        /// \param payloadFileName - A payload file name to be used in the TDF file
        TDFArchiveReader(std::istream& inStream,
                        const std::string& manifestFilename,
                        const std::string& payloadFileName);

        /// Delete default constructor
        TDFArchiveReader() = delete;

        /// Destructor
        ~TDFArchiveReader() = default;

        /// Read the exact size of payload contents into the buffer.
        /// \param buffer - WriteableBytes
        void readPayloadExact(WriteableBytes buffer);

        /// Not supported.
        TDFArchiveReader(const TDFArchiveReader &) = delete;
        TDFArchiveReader(TDFArchiveReader &&) = delete;
        TDFArchiveReader & operator=(const TDFArchiveReader &) = delete;
        TDFArchiveReader & operator=(TDFArchiveReader &&) = delete;

    public: // From TDFReader
        /// Get the manifest content.
        /// \return - Return the manifest as string.
        const std::string& getManifest() override { return m_manifest; };

        /// Read the payload contents into the buffer.
        /// The size of buffer could be less than requested size.
        /// \param buffer - WriteableBytes
        void readPayload(WriteableBytes& buffer) override;

        /// Get the size of the payload.
        /// \return std::uint64_t - Size of the payload.
        std::int64_t getPayloadSize() const override { return m_payloadSize; };

    private: /// static

        /// Libarchive callback to read the data.
        /// \param archive -  Pointer to the instance of an current archive struct.
        /// \param readerInstance -  An instance of the TDFArchiveReader.
        /// \param dataBlock - A pointer to data buffer.
        /// \return - Total bytes in buffer.
        static la_ssize_t readCallback(archive* , void* readerInstance, const void** dataBlock);

        /// Libarchive callback to skips at most request bytes from archive and returns the skipped amount.
        /// \param archive -  Pointer to the instance of an current archive struct.
        /// \param readerInstance -  An instance of the TDFArchiveReader.
        /// \param request - Skip at most request bytes.
        /// \return - Total bytes skiped.
        static la_int64_t skipCallback(archive* , void* readerInstance, la_int64_t request);

        /// Libarchive callback to seeks to specified location in the file and returns the position.
        /// \param archive -  Pointer to the instance of an current archive struct.
        /// \param readerInstance -  An instance of the TDFArchiveReader.
        /// \param offset - Seeks to the poistion specified by offset.
        /// \param whence - Whence values can be SEEK_SET, SEEK_CUR, SEEK_END.
        /// \return - The position.
        static la_int64_t seekCallback(archive* , void* readerInstance, la_int64_t offset, int whence);

    private:
        /// Create a archive with all the requiered settings.
        /// \return Unique ptr of archive
        ArchiveReadFreePtr createArchive();

    private: /// Data
        std::istream&                       m_inStream;
        ArchiveReadFreePtr                  m_archive;
        std::string                         m_manifest;
        std::vector<gsl::byte>              m_readBuffer;
        std::int64_t                        m_payloadSize;

    };
}  // namespace virtru

#endif //VIRTRU_TDF_ARCHIVE_READER_H
