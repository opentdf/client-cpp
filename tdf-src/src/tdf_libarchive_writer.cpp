//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/24
//  Copyright 2019 Virtru Corporation
//

#include "logger.h"
#include "tdf_exception.h"
#include "tdf_libarchive_writer.h"

namespace virtru {

    /// Constructor for TDFArchiveWriter
    TDFArchiveWriter::TDFArchiveWriter(DataSinkCb&& sinkCb,
                                       std::string manifestFilename,
                                       std::string payloadFileName,
                                       int64_t payloadSize) : m_sink { std::move(sinkCb) },
                                       m_manifestFilename{std::move(manifestFilename)}, m_payloadFileName{std::move(payloadFileName)},
                                       m_payloadSize{payloadSize} {

        // Initialize archive
        ArchiveFreePtr archive { archive_write_new() };

        if (!archive) {
            ThrowException("Archive writer initialization failed");
        }

        // Set the format as zip
        auto result = archive_write_set_format_zip(archive.get());
        if (result != ARCHIVE_OK) {
            std::string errorMsg { "Archive writer initialization failed - " };
            errorMsg.append(archive_error_string(archive.get()));
            ThrowException(std::move(errorMsg));
        }

        result = archive_write_zip_set_compression_store(archive.get());
        if (result != ARCHIVE_OK) {
            std::string errorMsg { "Archive writer initialization failed - " };
            errorMsg.append(archive_error_string(archive.get()));
            ThrowException(std::move(errorMsg));
        }

        result = archive_write_set_bytes_per_block(archive.get(), 0);
        if (result != ARCHIVE_OK) {
            std::string errorMsg { "Archive writer initialization failed - " };
            errorMsg.append(archive_error_string(archive.get()));
            ThrowException(std::move(errorMsg));
        }

        result = archive_write_open(archive.get(), this, nullptr, writeCallback, nullptr);
        if (result != ARCHIVE_OK) {
            std::string errorMsg { "Archive writer initialization failed - " };
            errorMsg.append(archive_error_string(archive.get()));
            ThrowException(std::move(errorMsg));
        }

        // Pass the ownership of the instance.
        m_archive = std::move(archive);
    }

    /// Append the manifest contents to the archive.
    void TDFArchiveWriter::appendManifest(std::string&& manifest) {

        // TODO: Check the tdf type - for now we assume it's tdf

        if (PayloadState::Appending != m_payloadState) {
            ThrowException("Manifest should archive at end.");
        }

        ArchiveEntryFreePtr entry { archive_entry_new() };

        archive_entry_set_pathname(entry.get(), m_manifestFilename.c_str());
        archive_entry_set_filetype(entry.get(), AE_IFREG);
        archive_entry_set_perm(entry.get(), 0755); // permission
        archive_entry_set_size(entry.get(), manifest.size());
        archive_entry_set_mtime(entry.get(), time(nullptr), 0);

        auto result = archive_write_header(m_archive.get(), entry.get());
        if (result != ARCHIVE_OK) {
            std::string errorMsg { "Failed to write manifest header zip entry - " };
            errorMsg.append(archive_error_string(m_archive.get()));
            ThrowException(std::move(errorMsg));
        }

        auto length = archive_write_data(m_archive.get(), manifest.data(), manifest.size());
        if (length < 0) {
            std::string errorMsg { "Failed to write manifest data - " };
            errorMsg.append(archive_error_string(m_archive.get()));
            ThrowException(std::move(errorMsg));
        }
    }

    /// Append the manifest contents to the archive.
    void TDFArchiveWriter::appendPayload(crypto::Bytes payload) {
        // TODO: Check the tdf type - for now we assume it's tdf

        if (PayloadState::Initial == m_payloadState) {

            ArchiveEntryFreePtr entry { archive_entry_new() };

            archive_entry_set_pathname(entry.get(), m_payloadFileName.c_str());
            archive_entry_set_filetype(entry.get(), AE_IFREG);
            archive_entry_set_perm (entry.get(), 0755); // permission
            archive_entry_set_size(entry.get(), m_payloadSize);
            archive_entry_set_mtime(entry.get(), time(nullptr), 0);

            auto result = archive_write_header(m_archive.get(), entry.get());
            if (result != ARCHIVE_OK) {
                std::string errorMsg { "Failed to write payload header zip entry - " };
                errorMsg.append(archive_error_string(m_archive.get()));
                ThrowException(std::move(errorMsg));
            }

            m_payloadState = PayloadState::Appending;
        }

        auto length = archive_write_data(m_archive.get(), payload.data(), payload.size());
        if (length < 0) {
            std::string errorMsg { "Failed to write payload data - " };
            errorMsg.append(archive_error_string(m_archive.get()));
            ThrowException(std::move(errorMsg));
        }
    }

    /// Finish the write operation.
    void TDFArchiveWriter::finish() {
        archive_write_close(m_archive.get());
    }


    /// Libarchive callback after the archive operation is complete.
    la_ssize_t TDFArchiveWriter::writeCallback(struct archive* archive, void* writerInstance, const void* buffer, size_t length) {

        std::ignore = archive;
        TDFArchiveWriter* writer = static_cast<TDFArchiveWriter*>(writerInstance);

        Bytes bytes { static_cast<const gsl::byte *>(buffer), static_cast< Bytes::index_type>(length) };
        auto status = writer->m_sink(bytes);

        if (Status::Success == status) {
            return bytes.size();
        } else {
            LogError("Sink callback failed.");
            return ARCHIVE_FAILED;
        }
    }
}  // namespace virtru
