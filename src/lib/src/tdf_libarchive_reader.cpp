/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/09/03
//

#include "logger.h"
#include "tdf_exception.h"
#include "tdf_libarchive_reader.h"

namespace virtru {

    // Read in chucks of 2mb
    constexpr int64_t kMaximumDataChunkSize = 2 * 1024 * 1024;

    /// Constructor for TDFArchiveReader
    TDFArchiveReader::TDFArchiveReader(std::istream& inStream,
            const std::string& manifestFilename,
            const std::string& payloadFileName) : m_inStream(inStream) {

        // Allocate space for read buffer.
        m_readBuffer.resize(kMaximumDataChunkSize);

        { /// Skip the payload and read the manifest.
            m_inStream.clear();
            m_inStream.seekg (0, m_inStream.beg);

            auto archiveFreePtr = createArchive();

            archive_entry* entry = nullptr;
            auto result = archive_read_next_header(archiveFreePtr.get(), &entry);
            if (result != ARCHIVE_OK) {
                std::string errorMsg { "Archive reader failed to read header - " };
                errorMsg.append(archive_error_string(archiveFreePtr.get()));
                ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
            }

            result = archive_read_next_header(archiveFreePtr.get(), &entry);
            if (result != ARCHIVE_OK) {
                std::string errorMsg { "Archive reader failed to read header - " };
                errorMsg.append(archive_error_string(archiveFreePtr.get()));
                ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
            }

            if (std::strncmp(archive_entry_pathname(entry), manifestFilename.c_str(), manifestFilename.size()) != 0) {
                std::string errorMsg { "Archive reader failed to find the manifest - " };
                errorMsg.append(manifestFilename);
                ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
            }

            // Read the contents of the manifest
            ByteArray<1024> buffer;
            while(true) {
                auto size = archive_read_data(archiveFreePtr.get(), buffer.data(), buffer.size());
                if (size < 0) {
                    std::string errorMsg { "Archive reader failed to read the manifest - " };
                    errorMsg.append(manifestFilename);
                    ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
                }

                // Done reading
                if (size == 0) {
                    break;
                }

                m_manifest.append(toChar(buffer.data()), size);
            }
        }

        { /// Read the manifest.

            m_inStream.clear();
            m_inStream.seekg (0, m_inStream.beg);

            m_archive = createArchive();

            archive_entry *entry = nullptr;
            auto result = archive_read_next_header(m_archive.get(), &entry);
            if (result != ARCHIVE_OK) {
                std::string errorMsg{"Archive reader failed to read header - "};
                errorMsg.append(archive_error_string(m_archive.get()));
                ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
            }

            if (std::strncmp(archive_entry_pathname(entry),
                             payloadFileName.c_str(), payloadFileName.size())) {
                std::string errorMsg{"Archive reader failed to find the payload - "};
                errorMsg.append(payloadFileName);
                ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
            }

            m_payloadSize = archive_entry_size(entry);
        }
    }

    /// Libarchive callback to read the data.
    la_ssize_t TDFArchiveReader::readCallback(archive* , void* readerInstance, const void** dataBlock) {

        TDFArchiveReader* reader = static_cast<TDFArchiveReader*>(readerInstance);

        auto& inStream = reader->m_inStream;
        auto& buffer = reader->m_readBuffer;

        if(inStream.read(toChar(buffer.data()), buffer.size())) {
            *dataBlock = buffer.data();
            return buffer.size();
        } else if (inStream.eof()) {
            *dataBlock = buffer.data();
            return inStream.gcount();
        } else {
            LogError("Source callback failed.");
            return ARCHIVE_FAILED;
        }
    }

    /// Libarchive callback to skips at most request bytes from archive and returns the skipped amount.
    la_int64_t TDFArchiveReader::skipCallback(archive* , void* readerInstance, la_int64_t request) {

        TDFArchiveReader* reader = static_cast<TDFArchiveReader*>(readerInstance);

        auto& inStream = reader->m_inStream;
        inStream.seekg(request, std::ios_base::cur);

        return request;
    }

    /// Libarchive callback to seeks to specified location in the file and returns the position.
    la_int64_t TDFArchiveReader::seekCallback(archive* , void* readerInstance, la_int64_t offset, int whence) {

        TDFArchiveReader* reader = static_cast<TDFArchiveReader*>(readerInstance);
        auto& inStream = reader->m_inStream;

        auto way = std::ios_base::beg; // SEEK_SET
        if (whence == SEEK_CUR) {
            way = std::ios_base::cur;
        } else if (whence == SEEK_END) {
            way = std::ios_base::end;
        }

        inStream.seekg(offset, way);

        return offset;
    }

    void TDFArchiveReader::readPayload(WriteableBytes& buffer) {
        const auto size = archive_read_data(m_archive.get(), buffer.data(), buffer.size());
        if (size < 0) {
            std::string errorMsg { "Archive reader failed to read - " };
            errorMsg.append(archive_error_string(m_archive.get()));
            ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
        } else if (size < buffer.size()) {
            std::string errorMsg { "Failed to read the bytes of size:" };
            errorMsg += std::to_string(buffer.size());
            LogError(errorMsg);
            buffer = buffer.first(size);
        }
    }

    void TDFArchiveReader::readPayloadExact(WriteableBytes buffer) {
        auto bufferSize = buffer.size();
        readPayload(buffer );
        if (buffer.size() != bufferSize) {
            ThrowException(std::move("Archive reader failed to read exact payload size"), VIRTRU_TDF_FORMAT_ERROR);
        }
    }

    ArchiveReadFreePtr TDFArchiveReader::createArchive() {

        ArchiveReadFreePtr archiveReadFreePtr {archive_read_new()};
        if (!archiveReadFreePtr) {
            ThrowException("Archive reader initialization failed");
        }

        auto result = archive_read_support_format_zip_streamable(archiveReadFreePtr.get());
        if (result != ARCHIVE_OK) {
            std::string errorMsg { "Archive reader initialization failed - " };
            errorMsg.append(archive_error_string(archiveReadFreePtr.get()));
            ThrowException(std::move(errorMsg));
        }

        result = archive_read_set_callback_data(archiveReadFreePtr.get(), this);
        if (result != ARCHIVE_OK) {
            std::string errorMsg { "Archive reader initialization failed - " };
            errorMsg.append(archive_error_string(archiveReadFreePtr.get()));
            ThrowException(std::move(errorMsg));
        }

        result = archive_read_set_read_callback(archiveReadFreePtr.get(), readCallback);
        if (result != ARCHIVE_OK) {
            std::string errorMsg { "Archive reader initialization failed - " };
            errorMsg.append(archive_error_string(archiveReadFreePtr.get()));
            ThrowException(std::move(errorMsg));
        }

        result = archive_read_set_skip_callback(archiveReadFreePtr.get(), skipCallback);
        if (result != ARCHIVE_OK) {
            std::string errorMsg { "Archive reader initialization failed - " };
            errorMsg.append(archive_error_string(archiveReadFreePtr.get()));
            ThrowException(std::move(errorMsg));
        }

        result = archive_read_set_seek_callback(archiveReadFreePtr.get(), seekCallback);
        if (result != ARCHIVE_OK) {
            std::string errorMsg { "Archive reader initialization failed - " };
            errorMsg.append(archive_error_string(archiveReadFreePtr.get()));
            ThrowException(std::move(errorMsg));
        }

        result = archive_read_open1(archiveReadFreePtr.get());
        if (result != ARCHIVE_OK) {
            std::string errorMsg { "Archive reader failed to open archived - " };
            errorMsg.append(archive_error_string(archiveReadFreePtr.get()));
            ThrowException("Archive reader failed to open archived - ");
        }

        return archiveReadFreePtr;
    }
} // namespace virtru
