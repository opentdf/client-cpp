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

#include <vector>

#include "tdf_archive_reader.h"
#include "tdf_exception.h"

namespace virtru {

    /// Constructor
    TDFArchiveReader::TDFArchiveReader(IInputProvider *inputProvider,
                                       const std::string &manifestFilename,
                                       const std::string &payloadFileName)
            : m_inputProvider(inputProvider),
              m_manifestFilename(manifestFilename),
              m_payloadFilename(payloadFileName) {
        parseZipArchive();
    }

    /// Read payload of length starting the index.
    void TDFArchiveReader::readPayload(size_t index, size_t length, WriteableBytes &bytes) {
        if (length > m_payloadSize) {
            std::string msg{"Payload length is too large"};
            LogError(msg);
            ThrowException(std::move(msg), VIRTRU_SYSTEM_ERROR);
        }

        m_inputProvider->readBytes(m_payloadStartIndex + index, length, bytes);
    }

    void TDFArchiveReader::parseZipArchive() {

        auto fileSize = m_inputProvider->getSize();

        EndOfCentralDirectoryRecord endOfCentralDirectoryRecord{};
        auto sizeOfEocdStruct = sizeof(endOfCentralDirectoryRecord);
        auto eocdStructBytes = gsl::make_span(reinterpret_cast<uint8_t *>(&endOfCentralDirectoryRecord),
                                              sizeOfEocdStruct);

        auto bytes = toWriteableBytes(eocdStructBytes);
        auto index = fileSize - sizeof(EndOfCentralDirectoryRecord);
        m_inputProvider->readBytes(index, sizeOfEocdStruct, bytes);

        if (endOfCentralDirectoryRecord.signature != static_cast<uint32_t>(ZipSignatures::EndOfCentralDirectorySignature)) {
            std::string errorMsg{"Could not read Zip End Of Central Directory Record"};
            LogError(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }

        // check if archive is zip64 header
        uint64_t entryCount = 0;
        size_t centralDirectoryStart = 0;
        bool isZip64 = false;
        if (endOfCentralDirectoryRecord.centralDirectoryOffset != ZIP64_MAGICVAL) {
            entryCount = endOfCentralDirectoryRecord.numberCentralDirectoryRecord;
            centralDirectoryStart = endOfCentralDirectoryRecord.centralDirectoryOffset;
        }
        else
        {
            isZip64 = true;
            Zip64EndOfCentralDirectoryRecordLocator zip64EndOfCentralDirectoryLocator{};
            auto sizeOfZip64EocdlStruct = sizeof(zip64EndOfCentralDirectoryLocator);
            index = fileSize - (sizeof(EndOfCentralDirectoryRecord) + sizeof(zip64EndOfCentralDirectoryLocator));

            auto zip64EocdStructBytes = gsl::make_span(reinterpret_cast<uint8_t *>(&zip64EndOfCentralDirectoryLocator),
                                                       sizeOfZip64EocdlStruct);
            bytes = toWriteableBytes(zip64EocdStructBytes);

            // Read zip64 End of Central Directory Locator
            m_inputProvider->readBytes(index, sizeOfZip64EocdlStruct, bytes);
            if (zip64EndOfCentralDirectoryLocator.signature != static_cast<uint32_t>(ZipSignatures::Zip64EndOfCentralDirectoryLocatorSignature)) {
                std::string errorMsg{"Could not read Zip64 End Of Central Directory Locator"};
                LogError(errorMsg);
                ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
            }

            Zip64EndOfCentralDirectoryRecord zip64EndOfCentralDirectoryRecord{};
            size_t sizeOfZip64EocdrStruct = sizeof(zip64EndOfCentralDirectoryRecord);

            auto zip64EocdrStructBytes = gsl::make_span(reinterpret_cast<uint8_t *>(&zip64EndOfCentralDirectoryRecord),
                                                        sizeOfZip64EocdrStruct);
            bytes = toWriteableBytes(zip64EocdrStructBytes);

            // Read zip64 End of Central Directory Record
            m_inputProvider->readBytes(zip64EndOfCentralDirectoryLocator.centralDirectoryOffset, sizeOfZip64EocdrStruct,
                                       bytes);
            if (zip64EndOfCentralDirectoryRecord.signature != static_cast<uint32_t>(ZipSignatures::Zip64EndOfCentralDirectorySignature)) {
                std::string errorMsg{"Could not read Zip64 End Of Central Directory"};
                LogError(errorMsg);
                ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
            }

            entryCount = zip64EndOfCentralDirectoryRecord.entryCountThisDisk;
            centralDirectoryStart = zip64EndOfCentralDirectoryRecord.startingDiskCentralDirectoryOffset;
        }

        CentralDirectoryFileHeader cdfh{};

        size_t nextLCD = 0;
        for (size_t i = 0; i < entryCount; ++i) {
            auto sizeOfCD = sizeof(CentralDirectoryFileHeader);
            auto cdStructBytes = gsl::make_span(reinterpret_cast<uint8_t *>(&cdfh), sizeOfCD);
            bytes = toWriteableBytes(cdStructBytes);

            index = nextLCD + centralDirectoryStart;
            // Read Central Directory Record
            m_inputProvider->readBytes(index, sizeOfCD, bytes);

            if (cdfh.signature != static_cast<uint32_t>(ZipSignatures::CentralFileHeaderSignature)) {
                std::string errorMsg{"Could not read Zip Central Directory File Header"};
                LogError(errorMsg);
                ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
            }

            std::string filename;
            filename.resize(cdfh.filenameLength);
            bytes = toWriteableBytes(filename);
            index += sizeOfCD;
            m_inputProvider->readBytes(index, cdfh.filenameLength, bytes);

            uint64_t offset = cdfh.localHeaderOffset; //if zip is 64 bit we read extra fields -  local header offset
            uint64_t bytesToRead = cdfh.compressedSize; //if zip is 64 bit we read extra fields - compressed size

            if(isZip64) {
                // Read Zip64 extended information extra fields

                // Read Zip64 Extended Information Extra Field Id
                uint16_t headerTag = 0;
                auto headerTagbytes = gsl::make_span(reinterpret_cast<uint8_t *>(&headerTag), sizeof(headerTag));
                bytes = toWriteableBytes(headerTagbytes);
                index += cdfh.filenameLength;
                m_inputProvider->readBytes(index,sizeof(uint16_t), bytes);

                // Read Zip64 Extended Information Extra Field Block Size
                uint16_t blocksize = 0;
                auto blocksizebytes = gsl::make_span(reinterpret_cast<uint8_t *>(&blocksize), sizeof(uint16_t));
                bytes = toWriteableBytes(blocksizebytes);
                index += sizeof(uint16_t);
                m_inputProvider->readBytes(index, sizeof(uint16_t), bytes);

                if (headerTag == ZIP64_EXTID) {
                    index += sizeof(uint16_t);
                    if (cdfh.compressedSize == ZIP64_MAGICVAL) {
                        uint64_t compressedSize = 0;
                        auto compressedSizebytes = gsl::make_span(reinterpret_cast<uint8_t *>(&compressedSize), sizeof(uint64_t));
                        bytes = toWriteableBytes(compressedSizebytes);
                        m_inputProvider->readBytes(index, sizeof(uint64_t), bytes);
                        bytesToRead = compressedSize;
                        index += sizeof(uint64_t);
                    }
                    if (cdfh.uncompressedSize == ZIP64_MAGICVAL) {
                        uint64_t uncompressedSize = 0;
                        auto uncompressedSizebytes = gsl::make_span(reinterpret_cast<uint8_t *>(&uncompressedSize), sizeof(uint64_t));
                        bytes = toWriteableBytes(uncompressedSizebytes);
                        m_inputProvider->readBytes(index, sizeof(uint64_t), bytes);
                        index += sizeof(uint64_t);
                    }
                    if (cdfh.localHeaderOffset == ZIP64_MAGICVAL) {
                        uint64_t localHeaderOffset = 0;
                        auto localHeaderOffsetbytes = gsl::make_span(reinterpret_cast<uint64_t *>(&localHeaderOffset),
                                                                     sizeof(uint64_t));
                        bytes = toWriteableBytes(localHeaderOffsetbytes);
                        m_inputProvider->readBytes(index, sizeof(uint64_t), bytes);
                        offset = localHeaderOffset;
                    }
                }
            }

            if (filename == m_manifestFilename) {
                parseFileHeaderForManifest(offset, bytesToRead);
            } else if (filename == m_payloadFilename) {
                parseFileHeaderForPayload(offset, bytesToRead);
            } else {
                std::string msg{"Invalid TDF format"};
                LogError(msg);
                ThrowException(std::move(msg), VIRTRU_SYSTEM_ERROR);
            }

            nextLCD = cdfh.extraFieldLength + cdfh.filenameLength + sizeOfCD;
        }

    }

    void TDFArchiveReader::parseFileHeaderForManifest(uint64_t offset, uint64_t lengthOfManifest) {

        uint64_t fileContentStart;
        LocalFileHeader lfh{};

        auto sizeOfLFH = sizeof(LocalFileHeader);
        auto lfhStructBytes = gsl::make_span(reinterpret_cast<uint8_t *>(&lfh), sizeOfLFH);
        auto bytes = toWriteableBytes(lfhStructBytes);

        m_inputProvider->readBytes(offset, sizeOfLFH, bytes);

        if (lfh.signature != static_cast<uint32_t>(ZipSignatures::LocalFileHeaderSignature)) {
            std::string errorMsg{"Could not read Zip Local File Header for manifest file"};
            LogError(errorMsg);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }

        // TODO: Check the filename is 0.manifest.json

        fileContentStart = offset + sizeof(LocalFileHeader) + lfh.filenameLength + lfh.extraFieldLength;
        m_manifest.resize(lengthOfManifest);
        auto manifestAsBytes = toWriteableBytes(m_manifest);
        m_inputProvider->readBytes(fileContentStart, lengthOfManifest, manifestAsBytes);
    }

    void TDFArchiveReader::parseFileHeaderForPayload(uint64_t offset, uint64_t lengthOfPayload) {
        LocalFileHeader lfh{};

        auto sizeOfLFH = sizeof(LocalFileHeader);
        auto lfhStructBytes = gsl::make_span(reinterpret_cast<uint8_t *>(&lfh), sizeOfLFH);
        auto bytes = toWriteableBytes(lfhStructBytes);

        m_inputProvider->readBytes(offset, sizeOfLFH, bytes);

        if (lfh.signature != static_cast<uint32_t>(ZipSignatures::LocalFileHeaderSignature)) {
            std::string msg{"Could not read Zip Local File Header for payload file"};
            LogError(msg);
            ThrowException(std::move(msg), VIRTRU_SYSTEM_ERROR);
        }

        m_payloadSize = lengthOfPayload;
        m_payloadStartIndex = offset + sizeof(LocalFileHeader) + lfh.filenameLength + lfh.extraFieldLength;
    }
}