/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/29
//
#include <cinttypes>

#include "crypto/asym_decryption.h"
#include "crypto/crypto_utils.h"
#include "encryption_strategy.h"
#include "key_access.h"
#include "logger.h"
#include "network/http_client_service.h"
#include "network/network_util.h"
#include "sdk_constants.h"
#include "splitkey_encryption.h"
#include "tdf_constants.h"
#include "tdf_exception.h"
#include "tdf_impl.h"
#include "tdfbuilder.h"
#include "tdf_xml_writer.h"
#include "tdf_xml_reader.h"
#include "tdfbuilder_impl.h"

#include <memory>
#include <boost/algorithm/string.hpp>
#include <boost/beast/core/detail/base64.hpp>
#include <boost/interprocess/streams/bufferstream.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include <istream>
#include <jwt-cpp/jwt.h>
#include <memory>
#include <regex>
#include <streambuf>

/// Time logs are only for non production builds.
#if VBUILD_BRANCH_PRODUCTION
#define LOGTIME 0
#else
#define LOGTIME 1
#endif

namespace virtru {

    // Constants
    constexpr auto firstTwoCharsOfZip = "PK";
    constexpr auto firstTwoCharsOfXML = "<?";

    using namespace virtru::network;
    using namespace boost::beast::detail::base64;
    using namespace boost::interprocess;

    /// Constants
    /// NOTE: To avoid extra padding when converting to base64 read always in multiples of 3 bytes.
    /// Noticed better performance around 500kb.
    static constexpr auto kZipReadSize = 540 * 1024;

    static const std::streampos kMaxFileSizeSupported = 68719476736; // 64GB

    /// Constructor
    TDFImpl::TDFImpl(TDFBuilder &tdfBuilder) : m_tdfBuilder(tdfBuilder) {

        LogTrace("TDFImpl::TDFImpl");

        // Reserve the size for buffers for .html protocol.
        if (m_tdfBuilder.m_impl->m_protocol == Protocol::Html) {
            m_zipReadBuffer.reserve(kZipReadSize);
            m_encodeBufferSize.reserve(encoded_size(kZipReadSize));
        }
    }

    /// Encrypt the file to tdf format.
    void TDFImpl::encryptFile(const std::string &inFilepath,
                               const std::string &outFilepath) {

        LogTrace("TDFImpl::EncryptFile");

        // Open the input file for reading.
        std::ifstream inStream{inFilepath, std::ios_base::in | std::ios_base::binary};
        if (!inStream) {
            std::string errorMsg{"Failed to open file for reading:"};
            errorMsg.append(inFilepath);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }

        // Open the tdf output file.
        std::ofstream outStream{outFilepath, std::ios_base::out | std::ios_base::binary};
        if (!outStream) {
            std::string errorMsg{"Failed to open file for writing:"};
            errorMsg.append(outFilepath);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }

        encryptStream(inStream, outStream);
    }

    /// Encrypt the stream data to tdf format.
    void TDFImpl::encryptStream(std::istream &inputStream, std::ostream &outStream) {

        LogTrace("TDFImpl::EncryptStream");

        // Reset the input stream.
        const auto final = gsl::finally([&inputStream] {
            inputStream.clear();
        });

#if LOGTIME
        auto t1 = std::chrono::high_resolution_clock::now();
#endif
        // The max file size of 64gb can be encrypted.
        inputStream.seekg(0, inputStream.end);
        auto fileSize = inputStream.tellg();
        if (fileSize > kMaxFileSizeSupported) {
            ThrowException("Current version of Virtru SDKs do not support file size greater than 64 GB.", VIRTRU_TDF_FORMAT_ERROR);
        }

        // Move back to the start.
        inputStream.seekg(0, inputStream.beg);

        if (m_tdfBuilder.m_impl->m_protocol == Protocol::Zip) { // .tdf format

            DataSinkCb libArchiveSinkCb = [&outStream](Bytes bytes) {
                if (!outStream.write(toChar(bytes.data()), bytes.size())) {
                    return Status::Failure;
                } else {
                    return Status::Success;
                }
            };

            auto tdfWriter = std::unique_ptr<TDFWriter>(new TDFArchiveWriter(std::move(libArchiveSinkCb),
                                                                             kTDFManifestFileName,
                                                                             kTDFPayloadFileName));

            encryptStream(inputStream, fileSize, *tdfWriter);

#if LOGTIME
            auto t2 = std::chrono::high_resolution_clock::now();
            auto tdfTimeSpent = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
            std::ostringstream os;
            os << ".tdf file encrypt time:" << tdfTimeSpent << "ms";
            LogInfo(os.str());
#endif
        } else { // .html or xml format

            std::string logMsg;
            if (m_tdfBuilder.m_impl->m_protocol == Protocol::Xml) {

                auto tdfWriter = std::unique_ptr<TDFXMLWriter>(new TDFXMLWriter(kTDFManifestFileName,
                                                                                 kTDFPayloadFileName));
                auto basePtr = static_cast<TDFWriter*>(tdfWriter.get());

                encryptStream(inputStream, fileSize, *basePtr);
                tdfWriter->writeToStream(outStream);
                logMsg = ".xml file encrypt time:";
            } else {

                std::stringstream tdfStream{};
                std::string manifest;

                // Finish creating a TDF before generating the HTML file
                {
                    DataSinkCb libArchiveSinkCb = [&tdfStream](Bytes bytes) {
                        if (!tdfStream.write(toChar(bytes.data()), bytes.size())) {
                            return Status::Failure;
                        } else {
                            return Status::Success;
                        }
                    };

                    auto tdfWriter = std::unique_ptr<TDFWriter>(new TDFArchiveWriter(std::move(libArchiveSinkCb),
                                                                                     kTDFManifestFileName,
                                                                                     kTDFPayloadFileName));

                    manifest = encryptStream(inputStream, fileSize, *tdfWriter);
                }

                generateHtmlTdf(manifest, tdfStream, outStream);
                LogTrace("after generateHtmlTdf");
                logMsg = ".html file encrypt time:";

            }

#if LOGTIME
            auto t2 = std::chrono::high_resolution_clock::now();
            auto htmlTimeSpent = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
            std::ostringstream os;
            os << logMsg << htmlTimeSpent << "ms";
            LogInfo(os.str());
#endif
        }
        LogTrace("exiting TDFImpl::EncryptStream");
    }

    /// Encrypt the data that is retrieved from the source callback.
    void TDFImpl::encryptData(TDFDataSourceCb sourceCb, TDFDataSinkCb sinkCb) {

        LogTrace("TDFImpl::encryptData");

        if (m_tdfBuilder.m_impl->m_protocol == Protocol::Xml) {
            ThrowException("XML TDF not supported for encryptData", VIRTRU_TDF_FORMAT_ERROR);
        }

#if LOGTIME
        auto t1 = std::chrono::high_resolution_clock::now();
#endif

        /// Read the all the data and store it in the stream.
        std::streampos streamSize;
        std::stringstream inStream;
        while (true) {
            Status status = Status::Success;
            auto bufferSpan = sourceCb(status);

            if (0 >= bufferSpan.dataLength) { // end of data
                break;
            }

            if (status == Status::Success) {
                streamSize += bufferSpan.dataLength;
                inStream.write((char *)(bufferSpan.data), bufferSpan.dataLength);
            } else {
                ThrowException("Source callback failed.", VIRTRU_SYSTEM_ERROR);
                break;
            }
        }

        if (m_tdfBuilder.m_impl->m_protocol == Protocol::Zip) { // .tdf format

            DataSinkCb libArchiveSinkCb = [&sinkCb](Bytes bytes) {
                BufferSpan bufferSpan{reinterpret_cast<const std::uint8_t *>(bytes.data()),
                                      static_cast<size_t>(bytes.size())};
                return sinkCb(bufferSpan);
            };

            auto tdfWriter = std::unique_ptr<TDFWriter>(new TDFArchiveWriter(std::move(libArchiveSinkCb),
                                                                             kTDFManifestFileName,
                                                                             kTDFPayloadFileName));

            encryptStream(inStream, streamSize, *tdfWriter);

#if LOGTIME
            auto t2 = std::chrono::high_resolution_clock::now();
            auto tdfTimeSpent = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
            std::ostringstream os;
            os << ".tdf file encrypt time:" << tdfTimeSpent << "ms";
            LogInfo(os.str());
#endif
        } else { // .html format

            std::stringstream tdfStream{};
            std::string manifest;

            // Finish creating a TDF before generating the HTML file
            {
                DataSinkCb libArchiveSinkCb = [&tdfStream](Bytes bytes) {
                    if (!tdfStream.write(toChar(bytes.data()), bytes.size())) {
                        return Status::Failure;
                    } else {
                        return Status::Success;
                    }
                };

                auto tdfWriter = std::unique_ptr<TDFWriter>(new TDFArchiveWriter(std::move(libArchiveSinkCb),
                                                                                 kTDFManifestFileName,
                                                                                 kTDFPayloadFileName));

                manifest = encryptStream(inStream, streamSize, *tdfWriter);
            }
            std::stringstream outStream;
            generateHtmlTdf(manifest, tdfStream, outStream);

            LogTrace("after generateHtmlTdf");

            // Invoke the caller.
            std::vector<char> buffer(10 * 1024);
            outStream.seekg(0, inStream.beg);
            while (!outStream.eof()) {
                outStream.read(buffer.data(), buffer.size());

                std::streamsize dataSize = outStream.gcount();
                BufferSpan bufferSpan{reinterpret_cast<const std::uint8_t *>(buffer.data()),
                                      static_cast<size_t>(dataSize)};

                auto status = sinkCb(bufferSpan);
                if (status != Status::Success) {
                    ThrowException("sink callback failed.", VIRTRU_SYSTEM_ERROR);
                }
            }
#if LOGTIME
            auto t2 = std::chrono::high_resolution_clock::now();
            auto htmlTimeSpent = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
            std::ostringstream os;
            os << ".html file encrypt time:" << htmlTimeSpent << "ms";
            LogInfo(os.str());
#endif
        }
        LogTrace("exiting TDFImpl::encryptData");
    }

    /// Decrypt the tdf stream data.
    void TDFImpl::decryptStreamPartial(std::istream &inStream, std::ostream &outStream, size_t offset, size_t length) {

        // Decrypt full stream
        // Redirect to outstream for requested portion
        // TODO - FIXME - PCM really inefficient implementation here
        std::stringstream tempStream;
        decryptStream(inStream, tempStream);

        tempStream.seekg(offset, std::ios_base::beg);
        for (size_t i = 0; i< length; i++) {
            uint8_t c = tempStream.get();
            outStream.put(c);
        }
    }

    /// Decrypt the tdf stream data.
    void TDFImpl::decryptStream(std::istream &inStream, std::ostream &outStream) {

        LogTrace("TDFImpl::decryptStream");

        // Reset the input stream.
        const auto final = gsl::finally([&inStream] {
            inStream.clear();
        });

#if LOGTIME
        auto t1 = std::chrono::high_resolution_clock::now();
#endif
        auto protocol = encryptedWithProtocol(inStream);
        if (protocol == Protocol::Zip) {
            TDFArchiveReader reader(inStream, kTDFManifestFileName, kTDFPayloadFileName);

            decryptStream(reader, [&outStream](Bytes bytes) {
                if (!outStream.write(toChar(bytes.data()), bytes.size())) {
                    return Status::Failure;
                } else {
                    return Status::Success;
                }
            });
        } else if (protocol == Protocol::Xml) {
            TDFXMLReader reader(inStream);
            decryptStream(reader, [&outStream](Bytes bytes) {
                if (!outStream.write(toChar(bytes.data()), bytes.size())) {
                    return Status::Failure;
                } else {
                    return Status::Success;
                }
            });
        } else { // html format

            /// TODO: Improve the memory effeciency for html parsing.
#if LOGTIME
            auto t11 = std::chrono::high_resolution_clock::now();
#endif
            // Get the stream size
            inStream.seekg(0, inStream.end);
            auto dataSize = inStream.tellg();
            inStream.seekg(0, inStream.beg);

            std::unique_ptr<std::uint8_t[]> buffer(new std::uint8_t[dataSize]);

            // Read all the data from input stream
            inStream.read(reinterpret_cast<char *>(buffer.get()), dataSize);

            auto bytes = gsl::make_span(buffer.get(), dataSize);
            auto tdfData = getTDFZipData(toBytes(bytes));

            bufferstream inputStream(reinterpret_cast<char *>(tdfData.data()), tdfData.size());
            TDFArchiveReader reader(inputStream, kTDFManifestFileName, kTDFPayloadFileName);

#if LOGTIME
            auto t12 = std::chrono::high_resolution_clock::now();
            std::ostringstream os;
            os << "Time spend extracting tdf data from html:" << std::chrono::duration_cast<std::chrono::milliseconds>(t12 - t11).count() << "ms";
            LogInfo(os.str());
#endif
            decryptStream(reader, [&outStream](Bytes bytes) {
                if (!outStream.write(toChar(bytes.data()), bytes.size())) {
                    return Status::Failure;
                } else {
                    return Status::Success;
                }
            });
        }

#if LOGTIME
        auto t2 = std::chrono::high_resolution_clock::now();
        auto timeSpent = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();

        std::ostringstream os;
        os << "Total decrypt-time:" << timeSpent << " ms";
        LogInfo(os.str());
#endif
        LogTrace("exiting TDFImpl::decryptStream");
    }

    /// Decrypt the tdf file.
    void TDFImpl::decryptFile(const std::string &inFilepath,
                               const std::string &outFilepath) {

        LogTrace("TDFImpl::decryptFile");

#if LOGTIME
        auto t1 = std::chrono::high_resolution_clock::now();
#endif


        // Open the input file for reading.
        std::ifstream inStream{inFilepath, std::ios_base::in | std::ios_base::binary};
        if (!inStream) {
            std::string errorMsg{"Failed to open file for reading:"};
            errorMsg.append(inFilepath);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }

        // Open the tdf output file.
        std::ofstream outStream{outFilepath, std::ios_base::out | std::ios_base::binary};
        if (!outStream) {
            std::string errorMsg{"Failed to open file for writing:"};
            errorMsg.append(outFilepath);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }

        auto protocol = encryptedWithProtocol(inStream);

        // Move back to the start.
        inStream.seekg(0, inStream.beg);

        if (protocol == Protocol::Zip) {
            TDFArchiveReader reader(inStream, kTDFManifestFileName, kTDFPayloadFileName);

            decryptStream(reader, [&outStream](Bytes bytes) {
                if (!outStream.write(toChar(bytes.data()), bytes.size())) {
                    return Status::Failure;
                } else {
                    return Status::Success;
                }
            });
        }  else if (protocol == Protocol::Xml) {
            TDFXMLReader reader(inStream);
            decryptStream(reader, [&outStream](Bytes bytes) {
                if (!outStream.write(toChar(bytes.data()), bytes.size())) {
                    return Status::Failure;
                } else {
                    return Status::Success;
                }
            });
        } else {
            /// TODO: Improve the memory effeciency for html parsing.
#if LOGTIME
            auto t11 = std::chrono::high_resolution_clock::now();
#endif
            auto tdfData = getTDFZipData(inFilepath);

            bufferstream inputStream(reinterpret_cast<char *>(tdfData.data()), tdfData.size());
            TDFArchiveReader reader(inputStream, kTDFManifestFileName, kTDFPayloadFileName);
#if LOGTIME
            auto t12 = std::chrono::high_resolution_clock::now();
            std::ostringstream os;
            os << "Time spend extracting tdf data from html:" << std::chrono::duration_cast<std::chrono::milliseconds>(t12 - t11).count() << "ms";
            LogInfo(os.str());
#endif
            decryptStream(reader, [&outStream](Bytes bytes) {
                if (!outStream.write(toChar(bytes.data()), bytes.size())) {
                    return Status::Failure;
                } else {
                    return Status::Success;
                }
            });
        }

#if LOGTIME
        auto t2 = std::chrono::high_resolution_clock::now();
        auto timeSpent = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();

        std::ostringstream os;
        os << "Total decrypt-time:" << timeSpent << " ms";
        LogInfo(os.str());
#endif
        LogTrace("exiting TDFImpl::decryptFile");
    }

    /// Decrypt the data that is retrieved from the source callback.
    void TDFImpl::decryptData(TDFDataSourceCb sourceCb, TDFDataSinkCb sinkCb) {

        LogTrace("TDFImpl::decryptData");

#if LOGTIME
        auto t1 = std::chrono::high_resolution_clock::now();
#endif

        /// Read the all the data and store it in the stream.
        std::streampos streamSize;
        std::stringstream inStream;
        while (true) {
            Status status = Status::Success;
            auto bufferSpan = sourceCb(status);

            if (0 >= bufferSpan.dataLength) { // end of data
                break;
            }

            if (status == Status::Success) {
                streamSize += bufferSpan.dataLength;
                inStream.write((char *)(bufferSpan.data), bufferSpan.dataLength);
            } else {
                ThrowException("Source callback failed.", VIRTRU_SYSTEM_ERROR);
                break;
            }
        }

        auto protocol = encryptedWithProtocol(inStream);
        if (protocol == Protocol::Zip) {
            TDFArchiveReader reader(inStream, kTDFManifestFileName, kTDFPayloadFileName);

            decryptStream(reader, [&sinkCb](Bytes bytes) {
                BufferSpan bufferSpan{reinterpret_cast<const std::uint8_t *>(bytes.data()),
                                      static_cast<size_t>(bytes.size())};
                return sinkCb(bufferSpan);
            });

        } else { // html format

            if (protocol == Protocol::Xml) {
                ThrowException("XML TDF not supported for decryptData", VIRTRU_TDF_FORMAT_ERROR);
            }

            /// TODO: Improve the memory effeciency for html parsing.
#if LOGTIME
            auto t11 = std::chrono::high_resolution_clock::now();
#endif
            // Get the stream size
            inStream.seekg(0, inStream.end);
            auto dataSize = inStream.tellg();
            inStream.seekg(0, inStream.beg);

            std::unique_ptr<std::uint8_t[]> buffer(new std::uint8_t[dataSize]);

            // Read all the data from input stream
            inStream.read(reinterpret_cast<char *>(buffer.get()), dataSize);

            auto bytes = gsl::make_span(buffer.get(), dataSize);
            auto tdfData = getTDFZipData(toBytes(bytes));

            bufferstream inputStream(reinterpret_cast<char *>(tdfData.data()), tdfData.size());
            TDFArchiveReader reader(inputStream, kTDFManifestFileName, kTDFPayloadFileName);

#if LOGTIME
            auto t12 = std::chrono::high_resolution_clock::now();
            std::ostringstream os;
            os << "Time spend extracting tdf data from html:" << std::chrono::duration_cast<std::chrono::milliseconds>(t12 - t11).count() << "ms";
            LogInfo(os.str());
#endif
            decryptStream(reader, [&sinkCb](Bytes bytes) {
                BufferSpan bufferSpan{reinterpret_cast<const std::uint8_t *>(bytes.data()),
                                      static_cast<size_t>(bytes.size())};
                return sinkCb(bufferSpan);
            });
        }

#if LOGTIME
        auto t2 = std::chrono::high_resolution_clock::now();
        auto timeSpent = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();

        std::ostringstream os;
        os << "Total decrypt-time:" << timeSpent << " ms";
        LogInfo(os.str());
#endif
        LogTrace("exiting TDFImpl::decryptData");
    }

    void TDFImpl::decryptStream(TDFReader& tdfReader, DataSinkCb &&sinkCB) {

        LogTrace("TDFImpl::decryptStream");

        auto manifestStr = tdfReader.getManifest();
        LogDebug("Manifest:" + manifestStr);

        auto manifest = nlohmann::json::parse(manifestStr);

#if LOGTIME
        auto unwrapKeyT1 = std::chrono::high_resolution_clock::now();
#endif

        WrappedKey wrappedKey = unwrapKey(manifest);

        LogDebug("Obtained the wrappedKey from manifest.");

#if LOGTIME
        auto unwrapKeyT2 = std::chrono::high_resolution_clock::now();
        auto unwrapTimeSpent = std::chrono::duration_cast<std::chrono::milliseconds>(unwrapKeyT2 - unwrapKeyT1).count();
        std::ostringstream os;
        os << "rewrap time: " << unwrapTimeSpent << "ms";
        LogInfo(os.str());
#endif
        // Get the algorithm and key type.
        std::string algorithm = manifest[kEncryptionInformation][kMethod][kCipherAlgorithm];
        std::string keyType = manifest[kEncryptionInformation][kEncryptKeyType];

        CipherType chiperType = CipherType::Aes265CBC;
        if (boost::iequals(algorithm, kCipherAlgorithmGCM)) {
            chiperType = CipherType::Aes256GCM;
        }

        if (!boost::iequals(keyType, kSplitKeyType)) {
            ThrowException("Only split key type is supported for tdf operations.", VIRTRU_CRYPTO_ERROR);
        }

        /// Create a split key and the key access object based on access type.
        auto splitKey = SplitKey{chiperType};
        splitKey.setWrappedKey(wrappedKey);

        auto &rootSignature = manifest[kEncryptionInformation][kIntegrityInformation][kRootSignature];
        std::string rootSignatureAlg = rootSignature[kRootSignatureAlg];
        std::string rootSignatureSig = rootSignature[kRootSignatureSig];

        // Get the hashes from the segments and combine.
        std::string aggregateHash;
        nlohmann::json segmentInfos = nlohmann::json::array();
        segmentInfos = manifest[kEncryptionInformation][kIntegrityInformation][kSegments];
        for (nlohmann::json segment : segmentInfos) {
            std::string hash = segment[kHash];
            aggregateHash.append(base64Decode(hash));
        }

        // Check the combined string of hashes
        auto payloadSigStr = getSignature(toBytes(aggregateHash), splitKey, rootSignatureAlg);
        if (rootSignatureSig != base64Encode(payloadSigStr)) {
            ThrowException("Failed integrity check on root signature", VIRTRU_CRYPTO_ERROR);
        }

        LogDebug("RootSignatureSig is validated.");

        auto &integrityInformation = manifest[kEncryptionInformation][kIntegrityInformation];

        // Check for default segment size.
        if (!integrityInformation.contains(kSegmentSizeDefault)) {
            ThrowException("SegmentSizeDefault is missing in tdf", VIRTRU_TDF_FORMAT_ERROR);
        }
        int segmentSizeDefault = integrityInformation[kSegmentSizeDefault];

        // Check for default encrypted segment size.
        if (!integrityInformation.contains(kEncryptedSegSizeDefault)) {
            ThrowException("EncryptedSegmentSizeDefault is missing in tdf", VIRTRU_TDF_FORMAT_ERROR);
        }
        int defaultEncryptedSegmentSize = integrityInformation[kEncryptedSegSizeDefault];

        ///
        // Create buffers for reading from file and for performing decryption.
        // These buffers will be reused.
        ///
        std::vector<gsl::byte> readBuffer(defaultEncryptedSegmentSize);
        std::vector<gsl::byte> decryptedBuffer(segmentSizeDefault);

        std::string segmentHashAlg = integrityInformation[kSegmentHashAlg];
        for (auto &segment : segmentInfos) {

            // Adjust read buffer size
            auto readBufferSpan = WriteableBytes{readBuffer};
            if (segment.contains(kEncryptedSegmentSize)) {
                int encryptedSegmentSize = segment[kEncryptedSegmentSize];
                readBufferSpan = WriteableBytes{readBufferSpan.data(), encryptedSegmentSize};
            }

            // Adjust decrypt buffer size
            auto outBufferSpan = WriteableBytes{decryptedBuffer};
            if (segment.contains(kSegmentSize)) {
                int segmentSize = segment[kSegmentSize];
                outBufferSpan = WriteableBytes{outBufferSpan.data(), segmentSize};
            }

            // Read form zip reader.
            tdfReader.readPayload(readBufferSpan);

            // Decrypt the payload.
            splitKey.decrypt(readBufferSpan, outBufferSpan);

            auto payloadSigStr = getSignature(readBufferSpan, splitKey, segmentHashAlg);
            std::string hash = segment[kHash];

            // Validate the hash.
            if (hash != base64Encode(payloadSigStr)) {
                ThrowException("Failed integrity check on segment hash", VIRTRU_CRYPTO_ERROR);
            }

            // Write to file.
            auto status = sinkCB({outBufferSpan.data(), outBufferSpan.size()});

            if (status != Status::Success) {
                ThrowException("Fail to write into stream", VIRTRU_SYSTEM_ERROR);
            }
        }
        LogTrace("exiting TDFImpl::decryptStream");
    }

    /// Encrypt the data in the input stream.
    std::string TDFImpl::encryptStream(std::istream& inputStream, std::streampos dataSize,
                                       TDFWriter& writer) {

        LogTrace("TDFImpl::encryptStream");

        // Check if there is a policy object
        if (m_tdfBuilder.m_impl->m_policyObject.getUuid().empty()) {
            ThrowException("Policy object is missing.", VIRTRU_TDF_FORMAT_ERROR);
        }

        if (m_tdfBuilder.m_impl->m_policyObject.getDissems().empty() &&
            m_tdfBuilder.m_impl->m_policyObject.getAttributeObjects().empty()) {
            LogWarn(kEmptyPolicyMsg);
        }

        /// Create a split key and the key access object based on access type.
        auto splitKey = SplitKey{m_tdfBuilder.m_impl->m_cipherType};

        auto keyAccessType = m_tdfBuilder.m_impl->m_keyAccessType;
        if (keyAccessType == KeyAccessType::Wrapped) {
            auto keyAccess = std::unique_ptr<KeyAccess>{std::make_unique<WrappedKeyAccess>(m_tdfBuilder.m_impl->m_kasUrl,
                                                                                           m_tdfBuilder.m_impl->m_kasPublicKey,
                                                                                           m_tdfBuilder.m_impl->m_policyObject,
                                                                                           m_tdfBuilder.m_impl->m_metadataAsJsonStr)};
            splitKey.addKeyAccess(std::move(keyAccess));

            LogDebug("KeyAccessType is wrapped");
        } else {

            if (m_tdfBuilder.m_impl->m_metadataAsJsonStr.empty()) {
                ThrowException("Remote key access type should have the meta data.", VIRTRU_TDF_FORMAT_ERROR);
            }

            auto keyAccess = std::unique_ptr<KeyAccess>{std::make_unique<RemoteKeyAccess>(m_tdfBuilder.m_impl->m_kasUrl,
                                                                                          m_tdfBuilder.m_impl->m_kasPublicKey,
                                                                                          m_tdfBuilder.m_impl->m_policyObject,
                                                                                          m_tdfBuilder.m_impl->m_metadataAsJsonStr)};
            splitKey.addKeyAccess(std::move(keyAccess));
            LogDebug("KeyAccessType is remote");
        }

        auto segIntegrityAlg = m_tdfBuilder.m_impl->m_segmentIntegrityAlgorithm;
        auto segIntegrityAlgStr = (segIntegrityAlg == IntegrityAlgorithm::HS256) ? kHmacIntegrityAlgorithm : kGmacIntegrityAlgorithm;
        auto integrityAlg = m_tdfBuilder.m_impl->m_integrityAlgorithm;
        auto integrityAlgStr = (integrityAlg == IntegrityAlgorithm::HS256) ? kHmacIntegrityAlgorithm : kGmacIntegrityAlgorithm;

        auto encryptionInformationJson = splitKey.getManifest();

        nlohmann::json payloadTypeObject;

        auto protocol = (m_tdfBuilder.m_impl->m_protocol == Protocol::Zip) ? kPayloadZipProtcol : kPayloadHtmlProtcol;
        payloadTypeObject[kPayloadReferenceType] = kPayloadReference;
        payloadTypeObject[kUrl] = kTDFPayloadFileName;
        payloadTypeObject[kProtocol] = protocol;
        payloadTypeObject[kPayloadMimeType] = m_tdfBuilder.m_impl->m_mimeType;
        payloadTypeObject[kPayloadIsEncrypted] = true;

        nlohmann::json manifest;

        manifest[kPayload] = payloadTypeObject;
        manifest[kEncryptionInformation] = encryptionInformationJson;

        auto ivSize = (m_tdfBuilder.m_impl->m_cipherType == CipherType::Aes256GCM) ? kGcmIvSize : kCbcIvSize;
        auto defaultSegmentSize = m_tdfBuilder.m_impl->m_segmentSize;

        ///
        // Create buffers for reading from file and for performing encryption.
        // These buffers will be reused.
        ///
        auto encryptedBufferSize = defaultSegmentSize + ivSize + kAesBlockSize;
        std::vector<char> readBuffer(defaultSegmentSize); // TODO: may want use gsl::byte instead of char
        std::vector<gsl::byte> encryptedBuffer(encryptedBufferSize);

#if LOGTIME
        auto upsertT1 = std::chrono::high_resolution_clock::now();
#endif
        /// upsert
        upsert(manifest);

#if LOGTIME
        auto upsertT2 = std::chrono::high_resolution_clock::now();
        auto upsertTimeSpent = std::chrono::duration_cast<std::chrono::milliseconds>(upsertT2 - upsertT1).count();
        std::ostringstream os;
        os << "upsert time: " << upsertTimeSpent << "ms";
        LogInfo(os.str());
#endif

        ///
        /// Read the file in chucks of 'segmentSize'
        ///
        std::string aggregateHash{};
        nlohmann::json segmentInfos = nlohmann::json::array();

        /// Calculate the actual size of the TDF payload.
        /// Formula totalSegment = quotient + possible one(if the data size is not exactly divisible by segment size)
        unsigned totalSegment = (dataSize / defaultSegmentSize) + ((dataSize % defaultSegmentSize == 0) ? 0 : 1);
        if (totalSegment == 0) { // For empty file we still want to create a payload.
            totalSegment = 1;
        }

        int64_t extraBytes = totalSegment * (ivSize + kAesBlockSize);
        std::streampos actualTDFPayloadSize = dataSize + extraBytes;

        LogDebug("Total segments:" + std::to_string(totalSegment));

        writer.setPayloadSize(actualTDFPayloadSize);

        while (totalSegment != 0) {

            // Read the file in 'defaultSegmentSize' chuck max
            inputStream.read(readBuffer.data(), defaultSegmentSize);

            // make sub span of 'defaultSegmentSize' or less
            auto readBufferAsBytes = toBytes(readBuffer);
            Bytes subSpanBuffer{readBufferAsBytes.data(), static_cast<std::ptrdiff_t>(inputStream.gcount())};
            auto writeableBytes = toWriteableBytes(encryptedBuffer);

            // Encrypt the payload
            splitKey.encrypt(subSpanBuffer, writeableBytes);

            ///
            // Check if all the bytes are encrypted.
            ///
            auto encryptedSize = inputStream.gcount() + ivSize + kAesBlockSize;
            if (writeableBytes.size() != encryptedSize) {
                ThrowException("Encrypted buffer output is not correct!", VIRTRU_TDF_FORMAT_ERROR);
            }

            // Generate signature for the encrypted payload.
            auto payloadSigStr = getSignature(writeableBytes, splitKey, segIntegrityAlg);

            // Append the aggregate payload signature.
            aggregateHash.append(payloadSigStr);

            nlohmann::json segmentInfo;
            segmentInfo[kHash] = base64Encode(payloadSigStr);
            segmentInfo[kSegmentSize] = readBuffer.size();
            segmentInfo[kEncryptedSegmentSize] = encryptedSize;
            segmentInfos.emplace_back(segmentInfo);

            // write the encrypted data to tdf file.
            writer.appendPayload(writeableBytes);

            totalSegment--;
        }

        LogDebug("Encryption is completed, preparing the manifest");

        auto aggregateHashSigStr = getSignature(toBytes(aggregateHash), splitKey, integrityAlg);

        manifest[kEncryptionInformation][kIntegrityInformation][kRootSignature][kRootSignatureSig] = base64Encode(aggregateHashSigStr);
        manifest[kEncryptionInformation][kIntegrityInformation][kRootSignature][kRootSignatureAlg] = integrityAlgStr;

        manifest[kEncryptionInformation][kIntegrityInformation][kSegmentSizeDefault] = defaultSegmentSize;
        manifest[kEncryptionInformation][kIntegrityInformation][kEncryptedSegSizeDefault] = encryptedBufferSize;
        manifest[kEncryptionInformation][kIntegrityInformation][kSegmentHashAlg] = segIntegrityAlgStr;

        manifest[kEncryptionInformation][kIntegrityInformation][kSegments] = segmentInfos;
        manifest[kEncryptionInformation][kMethod][kIsStreamable] = true;

        writer.appendManifest(to_string(manifest));

        LogTrace("exiting TDFImpl::encryptStream");

        return to_string(manifest);
    }

    void TDFImpl::generateHtmlTdf(const std::string &manifest,
                                   std::istream &inputStream,
                                   std::ostream &outStream) {

        LogTrace("TDFImpl::generateHtmlTdf");

        using namespace boost::beast::detail::base64;

        auto const &token1 = m_tdfBuilder.m_impl->m_htmlTemplateTokens[0];
        LogTrace("before token1 write");
        outStream.write(token1.data(), token1.size());

        /// 1 - Write the contents of the tdf in base64
        std::size_t actualEncodedBufSize;

        // Vectors m_encodeBufferSize and m_zipReadBuffer are sized in constructor if protocol is html
        while (!inputStream.eof() && !inputStream.fail()) {

            // Read from the file.
            LogTrace("before zip read");
            inputStream.read(reinterpret_cast<char *>(m_zipReadBuffer.data()), kZipReadSize);

            // Encode the tdf zip data.
            actualEncodedBufSize = encode(m_encodeBufferSize.data(), m_zipReadBuffer.data(), inputStream.gcount());

            // Write to the html file
            LogTrace("before encoded data write");
            outStream.write(reinterpret_cast<char *>(m_encodeBufferSize.data()), actualEncodedBufSize);
        }

        auto const &token2 = m_tdfBuilder.m_impl->m_htmlTemplateTokens[1];
        LogTrace("before token1 write");
        outStream.write(token2.data(), token2.size());

        /// 2 - Write the contents of the manifest in base64

        // manifest can grow larger than our prealloc'ed buffer, correct that if it's a problem
        unsigned manifestEncodedSize = encoded_size(manifest.size());
        if (manifestEncodedSize > m_encodeBufferSize.size()) {
            m_encodeBufferSize.resize(manifestEncodedSize);
        }
        actualEncodedBufSize = encode(m_encodeBufferSize.data(), manifest.data(), manifest.size());
        LogTrace("before manifest write");
        outStream.write(reinterpret_cast<char *>(m_encodeBufferSize.data()), actualEncodedBufSize);

        auto const &token3 = m_tdfBuilder.m_impl->m_htmlTemplateTokens[2];
        LogTrace("before token3 write");
        outStream.write(token3.data(), token3.size());

        /// 3 - Write the secure reader url.
        const auto &url = m_tdfBuilder.m_impl->m_secureReaderUrl;
        LogTrace("before sr url write");
        outStream.write(url.data(), url.size());

        auto const &token4 = m_tdfBuilder.m_impl->m_htmlTemplateTokens[3];
        LogTrace("before token4 write");
        outStream.write(token4.data(), token4.size());

        /// 4 - Write the secure reader base url.
        std::regex urlRegex("(http|https)://([^/ ]+)(/?[^ ]*)");
        std::cmatch what;
        if (!regex_match(url.c_str(), what, urlRegex)) {
            std::string errorMsg{"Failed to parse url, expected:'(http|https)//<domain>/<target>' actual:"};
            errorMsg.append(url);
            ThrowException(std::move(errorMsg));
        }

        std::ostringstream targetBaseUrl;
        targetBaseUrl << std::string(what[1].first, what[1].second) << "://";
        targetBaseUrl << std::string(what[2].first, what[2].second);

        auto targetBaseUrlStr = targetBaseUrl.str();
        LogTrace("before base url write");
        outStream.write(targetBaseUrlStr.data(), targetBaseUrlStr.size());

        auto const &token5 = m_tdfBuilder.m_impl->m_htmlTemplateTokens[4];
        LogTrace("before token5 write");
        outStream.write(token5.data(), token5.size());

        /// 5 - Write he secure reader url for window.location.href - 1
        LogTrace("before sr url write 2");
        outStream.write(url.data(), url.size());

        auto const &token6 = m_tdfBuilder.m_impl->m_htmlTemplateTokens[5];
        LogTrace("before token6 write");
        outStream.write(token6.data(), token6.size());

        /// 6 - Write he secure reader url for window.location.href - 2
        LogTrace("before sr url write 2");
        outStream.write(url.data(), url.size());

        auto const &token7 = m_tdfBuilder.m_impl->m_htmlTemplateTokens[6];
        LogTrace("before token7 write");
        outStream.write(token7.data(), token7.size());

        LogTrace("exiting TDFImpl::generateHtmlTdf");
    }


    bool TDFImpl::isStreamTDF(std::istream &inStream) {
        LogTrace("TDFImpl::isStreamTDF");

        // Reset the input stream.
        const auto final = gsl::finally([&inStream] {
            inStream.clear();
        });

        auto protocol = encryptedWithProtocol(inStream);
        try
        {
            if (protocol == Protocol::Zip) {
                TDFArchiveReader reader(inStream, kTDFManifestFileName, kTDFPayloadFileName);
                return true;

            } else if (protocol == Protocol::Xml) {
                TDFXMLReader reader(inStream);
                reader.getManifest();
                reader.getPayloadSize();
                return true;

            } else {
                // Get the stream size
                inStream.seekg(0, inStream.end);
                auto dataSize = inStream.tellg();
                inStream.seekg(0, inStream.beg);

                std::unique_ptr<std::uint8_t[]> buffer(new std::uint8_t[dataSize]);

                // Read all the data from input stream
                inStream.read(reinterpret_cast<char *>(buffer.get()), dataSize);

                auto bytes = gsl::make_span(buffer.get(), dataSize);
                auto tdfData = getTDFZipData(toBytes(bytes));
                auto manifestData = getTDFZipData(toBytes(bytes), true);
                bufferstream inputStream(reinterpret_cast<char *>(tdfData.data()), tdfData.size());
                TDFArchiveReader reader(inputStream, kTDFManifestFileName, kTDFPayloadFileName);
                
                return true;
            }
        }
        catch (const Exception &exception)
        {
            return false;
        }
    }
  

    /// Decrypt and return TDF metadata as a string. If the TDF content has
    /// no encrypted metadata, will return an empty string.
    std::string TDFImpl::getEncryptedMetadata(std::istream& inStream) {
        LogTrace("TDFImpl::getEncryptedMetadata");

        auto manifestStr = getManifest(inStream);
        auto manifest = nlohmann::json::parse(manifestStr);
        nlohmann::json keyAccessObjects = nlohmann::json::array();
        keyAccessObjects = manifest[kEncryptionInformation][kKeyAccess];
        if (keyAccessObjects.size() != 1) {
            ThrowException("Only supports one key access object - unwrap", VIRTRU_TDF_FORMAT_ERROR);
        }

        // First object
        auto &keyAccess = keyAccessObjects.at(0);
        if (!keyAccess.contains(kEncryptedMetadata)) {
            LogWarn("There is no metadata in tdf");
            return {};
        }

        std::string encryptedMetadata = keyAccess[kEncryptedMetadata];
        WrappedKey wrappedKey = unwrapKey(manifest);

        // Get the algorithm and key type.
        std::string algorithm = manifest[kEncryptionInformation][kMethod][kCipherAlgorithm];
        std::string keyType = manifest[kEncryptionInformation][kEncryptKeyType];

        CipherType chiperType = CipherType::Aes265CBC;
        if (boost::iequals(algorithm, kCipherAlgorithmGCM)) {
            chiperType = CipherType::Aes256GCM;
        }

        if (!boost::iequals(keyType, kSplitKeyType)) {
            ThrowException("Only split key type is supported for tdf operations.", VIRTRU_CRYPTO_ERROR);
        }

        /// Create a split key and the key access object based on access type.
        auto splitKey = SplitKey{chiperType};
        splitKey.setWrappedKey(wrappedKey);

        auto metadataJsonStr = base64Decode(encryptedMetadata);
        auto metadataJsonObj = nlohmann::json::parse(metadataJsonStr);
        auto metadataAsCipherText = metadataJsonObj[kCiphertext].get<std::string>();

        auto metadataCipherTextAsBinary = base64Decode(metadataAsCipherText);
        auto readBufferSpan = toBytes(metadataCipherTextAsBinary);
        std::vector<char> metadataAsString(metadataCipherTextAsBinary.length() - (kAesBlockSize + kGcmIvSize));

        auto writeableBytes = toWriteableBytes(metadataAsString);
        splitKey.decrypt(readBufferSpan, writeableBytes);

        std::string metadata(metadataAsString.begin(), metadataAsString.end());
        return metadata;
    }

    /// Return the policy JSON string from the tdf input stream.
    std::string TDFImpl::getPolicy(std::istream &inStream) {

        LogTrace("TDFImpl::getPolicy stream");

        auto manifestStr = getManifest(inStream);
        return getPolicyFromManifest(manifestStr);
    }

    /// Return the policy uuid from the tdf file.
    std::string TDFImpl::getPolicyUUID(const std::string &tdfFilePath) {

        LogTrace("TDFImpl::getPolicyUUID file");

        std::string manifestStr;

        auto protocol = encryptedWithProtocol(tdfFilePath);
        if (protocol == Protocol::Zip) {

            // Open the input file for reading.
            std::ifstream inStream{tdfFilePath, std::ios_base::in | std::ios_base::binary};
            if (!inStream) {
                std::string errorMsg{"Failed to open file for reading:"};
                errorMsg.append(tdfFilePath);
                ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
            }

            TDFArchiveReader reader(inStream, kTDFManifestFileName, kTDFPayloadFileName);
            manifestStr = reader.getManifest();

        } else {

            if (protocol == Protocol::Xml) {
                ThrowException("XML TDF not supported", VIRTRU_TDF_FORMAT_ERROR);
            }

            auto tdfData = getTDFZipData(tdfFilePath, true);
            manifestStr.append(tdfData.begin(), tdfData.end());
        }

        return getPolicyIdFromManifest(manifestStr);
    }

    /// Return the policy uuid from the tdf input stream.
    std::string TDFImpl::getPolicyUUID(std::istream &inStream) {

        LogTrace("TDFImpl::getPolicyUUID stream");

        // Reset the input stream.
        const auto final = gsl::finally([&inStream] {
            inStream.clear();
        });

        std::string manifestStr;

        auto protocol = encryptedWithProtocol(inStream);
        if (protocol == Protocol::Zip) {
            TDFArchiveReader reader(inStream, kTDFManifestFileName, kTDFPayloadFileName);

            manifestStr = reader.getManifest();
        } else { // html format

            if (protocol == Protocol::Xml) {
                ThrowException("XML TDF not supported", VIRTRU_TDF_FORMAT_ERROR);
            }

            // Get the stream size
            inStream.seekg(0, inStream.end);
            auto dataSize = inStream.tellg();
            inStream.seekg(0, inStream.beg);

            std::unique_ptr<std::uint8_t[]> buffer(new std::uint8_t[dataSize]);

            // Read all the data from input stream
            inStream.read(reinterpret_cast<char *>(buffer.get()), dataSize);

            auto bytes = gsl::make_span(buffer.get(), dataSize);
            auto manifestData = getTDFZipData(toBytes(bytes), true);

            manifestStr.append(manifestData.begin(), manifestData.end());
        }

        return getPolicyIdFromManifest(manifestStr);
    }

    /// Sync the tdf file, with symmetric wrapped key and Policy Object.
    void TDFImpl::sync(const std::string &encryptedTdfFilepath) const {

        LogTrace("TDFImpl::sync");

        std::string manifestStr;

        auto protocol = encryptedWithProtocol(encryptedTdfFilepath);
        if (protocol == Protocol::Zip) {
            // Open the input file for reading.
            std::ifstream inputStream{encryptedTdfFilepath, std::ios_base::in | std::ios_base::binary};
            if (!inputStream) {
                std::string errorMsg{"Failed to open file for reading:"};
                errorMsg.append(encryptedTdfFilepath);
                ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
            }

            TDFArchiveReader reader(inputStream, kTDFManifestFileName, kTDFPayloadFileName);
            manifestStr = reader.getManifest();
        } else {

            if (protocol == Protocol::Xml) {
                ThrowException("XML TDF not supported", VIRTRU_TDF_FORMAT_ERROR);
            }

            auto tdfData = getTDFZipData(encryptedTdfFilepath, true);
            manifestStr.append(tdfData.begin(), tdfData.end());
        }

        auto manifest = nlohmann::json::parse(manifestStr);

        if (!manifest.contains(kEncryptionInformation)) {
            std::string errorMsg{"'encryptionInformation' not found in the manifest of tdf -"};
            errorMsg.append(encryptedTdfFilepath);
            ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
        }

        auto &encryptionInformation = manifest[kEncryptionInformation];

        if (!encryptionInformation.contains(kKeyAccess)) {
            std::string errorMsg{"'keyAccess' not found in the manifest of tdf -"};
            errorMsg.append(encryptedTdfFilepath);
            ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
        }

        nlohmann::json keyAccessObjects = nlohmann::json::array();
        keyAccessObjects = encryptionInformation[kKeyAccess];
        if (keyAccessObjects.size() != 1) {
            ThrowException("Only supports one key access object.", VIRTRU_TDF_FORMAT_ERROR);
        }

        // First object
        auto &keyAccess = keyAccessObjects.at(0);
        std::string encryptedKeyType = keyAccess[kEncryptKeyType];

        if (!boost::iequals(encryptedKeyType, kKeyAccessWrapped)) {
            LogWarn("Sync should be performed only on 'wrapped' encrypted key type.");
        }

        upsert(manifest, true);
    }

    /// Generate a signature of the payload base on integrity algorithm.
    std::string TDFImpl::getSignature(Bytes payload, SplitKey &splitkey, IntegrityAlgorithm alg) const {

        LogTrace("TDFImpl::getSignature IA alg");

        constexpr auto kGmacPayloadLength = 16;

        switch (alg) {
        case IntegrityAlgorithm::HS256:

            return hexHmacSha256(payload, splitkey.getWrappedKey());

        case IntegrityAlgorithm::GMAC:
            if (kGmacPayloadLength > payload.size()) {
                ThrowException("Failed to create GMAC signature, invalid payload size.", VIRTRU_CRYPTO_ERROR);
            }

            return hex(payload.last(kGmacPayloadLength));
        default:
            ThrowException("Unknown algorithm, can't calculate signature.", VIRTRU_CRYPTO_ERROR);
            break;
        }
        return std::string{};
    }

    /// Generate a signature of the payload base on integrity algorithm.
    std::string TDFImpl::getSignature(Bytes payload, SplitKey &splitkey, const std::string &alg) const {

        LogTrace("TDFImpl::getSignature string alg");

        if (boost::iequals(alg, kHmacIntegrityAlgorithm)) {
            return getSignature(payload, splitkey, IntegrityAlgorithm::HS256);
        } else {
            return getSignature(payload, splitkey, IntegrityAlgorithm::GMAC);
        }
    }

    std::string TDFImpl::buildUpsertV2Payload(nlohmann::json &requestBody) const {

        LogTrace("TDFImpl::buildUpsertV2Payload");

        requestBody[kClientPublicKey] = m_tdfBuilder.m_impl->m_publicKey;

        auto now = std::chrono::system_clock::now();
        std::string requestBodyAsStr = requestBody.dump();

        // Generate a token which expires in a min.
        auto builder = jwt::create()
                .set_type(kAuthTokenType)
                .set_issued_at(now)
                .set_expires_at(now + std::chrono::seconds{60})
                .set_payload_claim(kRequestBody, jwt::claim(requestBodyAsStr));

        nlohmann::json signedTokenRequestBody;
        std::string signedToken;

        signedToken = builder.sign(jwt::algorithm::rs256(m_tdfBuilder.m_impl->m_requestSignerPublicKey,
                                                             m_tdfBuilder.m_impl->m_requestSignerPrivateKey));

        signedTokenRequestBody[kSignedRequestToken] = signedToken;
        auto signedTokenRequestBodyStr = to_string(signedTokenRequestBody);

        return signedTokenRequestBodyStr;
    }

    void TDFImpl::buildUpsertV1Payload(nlohmann::json &requestBody) const {

        LogTrace("TDFImpl::buildUpsertV1Payload");

        // Generate a token which expires in a min.
        auto now = std::chrono::system_clock::now();
        auto authToken = jwt::create()
                             .set_type(kAuthTokenType)
                             .set_issued_at(now)
                             .set_expires_at(now + std::chrono::seconds{60})
                             .sign(jwt::algorithm::rs256(m_tdfBuilder.m_impl->m_publicKey,
                                                         m_tdfBuilder.m_impl->m_privateKey));

        requestBody[kAuthToken] = authToken;

        // Add entity object
        auto entityJson = nlohmann::json::parse(m_tdfBuilder.m_impl->m_entityObject.toJsonString());
        requestBody[kEntity] = entityJson;
    }

    /// Upsert the key information.
    void TDFImpl::upsert(nlohmann::json &manifest, bool ignoreKeyAccessType) const {

        LogTrace("TDFImpl::upsert");

        if (!ignoreKeyAccessType && m_tdfBuilder.m_impl->m_keyAccessType == KeyAccessType::Wrapped) {
            LogDebug("Bypass upsert for wrapped key type.");
            return;
        }

        nlohmann::json requestBody;
        std::string upsertUrl;

        auto &keyAccessObjects = manifest[kEncryptionInformation][kKeyAccess];
        if (keyAccessObjects.size() != 1) {
            ThrowException("Only supports one key access object - upsert", VIRTRU_TDF_FORMAT_ERROR);
        }

        // First object
        auto &keyAccess = keyAccessObjects.at(0);

        // Request body
        requestBody[kKeyAccess] = keyAccess;

        // 'Policy' should hold the base64 encoded policy object.
        LogDebug("Policy object: " + m_tdfBuilder.m_impl->m_policyObject.toJsonString());
        requestBody[kPolicy] = base64Encode(m_tdfBuilder.m_impl->m_policyObject.toJsonString());

        //Upsert and Rewrap V2 require OIDC and different payloads
        std::string upsertRequestBody;
        if (m_tdfBuilder.m_impl->m_oidcMode) {
            upsertRequestBody = buildUpsertV2Payload(requestBody);
            upsertUrl = m_tdfBuilder.m_impl->m_kasUrl + kUpsertV2;
        } else {
            buildUpsertV1Payload(requestBody);
            upsertRequestBody = to_string(requestBody);
            upsertUrl = m_tdfBuilder.m_impl->m_kasUrl + kUpsert;
        }

        LogDebug(upsertRequestBody);

        unsigned status = kHTTPBadRequest;
        std::string upsertResponse;

        auto sp = m_tdfBuilder.m_impl->m_networkServiceProvider.lock();
        if (!sp) {
            ThrowException("Network service not available", VIRTRU_NETWORK_ERROR);
        }

        std::promise<void> upsertPromise;
        auto upsertFuture = upsertPromise.get_future();

        sp->executePost(upsertUrl, m_tdfBuilder.m_impl->m_httpHeaders, std::move(upsertRequestBody),
                        [&upsertPromise, &upsertResponse, &status](unsigned int statusCode, std::string &&response) {
                            status = statusCode;
                            upsertResponse = response.data();

                            upsertPromise.set_value();
                        });

        upsertFuture.get();

        // Handle HTTP error.
        if (status != kHTTPOk) {
            std::ostringstream os;
            os << "Upsert failed status:"
               << status << " response:" << upsertResponse;
            ThrowException(os.str(), VIRTRU_NETWORK_ERROR);
        }

        // Remove the 'encryptedMetadata' and  'wrappedkey' from manifest.
        auto encryptedMetaData = keyAccess.contains(kEncryptedMetadata);
        if (encryptedMetaData) {
            keyAccess.erase(kEncryptedMetadata);
        }

        keyAccess.erase(kWrappedKey);
        keyAccess.erase(kPolicyBinding);
    }

    std::string TDFImpl::buildRewrapV2Payload(nlohmann::json &requestBody) const {

        LogTrace("TDFImpl::buildRewrapV2Payload");

        requestBody[kClientPublicKey] = m_tdfBuilder.m_impl->m_publicKey;

        auto now = std::chrono::system_clock::now();
        std::string requestBodyAsStr = requestBody.dump();

        // Generate a token which expires in a min.
        auto builder = jwt::create()
                .set_type(kAuthTokenType)
                .set_issued_at(now)
                .set_expires_at(now + std::chrono::seconds{60})
                .set_payload_claim(kRequestBody, jwt::claim(requestBodyAsStr));

        nlohmann::json signedTokenRequestBody;
        std::string signedToken;

        signedToken = builder.sign(jwt::algorithm::rs256(m_tdfBuilder.m_impl->m_requestSignerPublicKey,
                                                         m_tdfBuilder.m_impl->m_requestSignerPrivateKey));

        signedTokenRequestBody[kSignedRequestToken] = signedToken;
        auto signedTokenRequestBodyStr = to_string(signedTokenRequestBody);

        return signedTokenRequestBodyStr;
    }

    void TDFImpl::buildRewrapV1Payload(nlohmann::json &requestBody) const {

        LogTrace("TDFImpl::buildRewrapV1Payload");

        // Generate a token which expires in a min.
        auto now = std::chrono::system_clock::now();
        auto authToken = jwt::create()
                             .set_type(kAuthTokenType)
                             .set_issued_at(now)
                             .set_expires_at(now + std::chrono::seconds{60})
                             .sign(jwt::algorithm::rs256(m_tdfBuilder.m_impl->m_publicKey,
                                                         m_tdfBuilder.m_impl->m_privateKey));

        // Add entity object
        auto entityJson = nlohmann::json::parse(m_tdfBuilder.m_impl->m_entityObject.toJsonString());
        requestBody[kEntity] = entityJson;
        requestBody[kAuthToken] = authToken;
    }

    /// Unwrap the key from the manifest.
    WrappedKey TDFImpl::unwrapKey(nlohmann::json &manifest) const {

        LogTrace("TDFImpl::unwrapKey");

        nlohmann::json keyAccessObjects = nlohmann::json::array();
        keyAccessObjects = manifest[kEncryptionInformation][kKeyAccess];
        if (keyAccessObjects.size() != 1) {
            ThrowException("Only supports one key access object - unwrap", VIRTRU_TDF_FORMAT_ERROR);
        }

        // First object
        auto &keyAccess = keyAccessObjects.at(0);

        // Request body
        nlohmann::json requestBody;
        std::string rewrapUrl;
        requestBody[kKeyAccess] = keyAccess;

        auto &policy = manifest[kEncryptionInformation][kPolicy];
        requestBody[kPolicy] = policy;

        std::string requestBodyStr;
        //Upsert and Rewrap V2 require OIDC and different payloads
        if (m_tdfBuilder.m_impl->m_oidcMode) {
            requestBodyStr = buildRewrapV2Payload(requestBody);
            rewrapUrl = m_tdfBuilder.m_impl->m_kasUrl + kRewrapV2;
        } else {
            buildRewrapV1Payload(requestBody);
            requestBodyStr = to_string(requestBody);
            rewrapUrl = m_tdfBuilder.m_impl->m_kasUrl + kRewrap;
        }

        LogDebug(requestBodyStr);

        unsigned status = kHTTPBadRequest;
        std::string rewrapResponse;

        auto sp = m_tdfBuilder.m_impl->m_networkServiceProvider.lock();
        if (!sp) {
            ThrowException("Network service not available", VIRTRU_NETWORK_ERROR);
        }

        std::promise<void> rewrapPromise;
        auto rewrapFuture = rewrapPromise.get_future();

        sp->executePost(rewrapUrl, m_tdfBuilder.m_impl->m_httpHeaders, std::move(requestBodyStr),
                            [&rewrapPromise, &rewrapResponse, &status](unsigned int statusCode, std::string &&response) {
            status = statusCode;
            rewrapResponse = response.data();

            rewrapPromise.set_value();
        });

        rewrapFuture.get();

        // Handle HTTP error.
        if (status != kHTTPOk) {
            std::ostringstream os;
            os << "rewrap failed status:"
               << status << " response:" << rewrapResponse;
            ThrowException(os.str(), VIRTRU_NETWORK_ERROR);
        }

        return getWrappedKey(rewrapResponse);
    }

    /// Parse the response and retrive the wrapped key.
    WrappedKey TDFImpl::getWrappedKey(const std::string &unwrapResponse) const {

        LogTrace("TDFImpl::getWrappedKey");
        nlohmann::json rewrappedObj;
        try{
            rewrappedObj = nlohmann::json::parse(unwrapResponse);
        } catch (...){
            if (unwrapResponse == ""){
                ThrowException("No rewrap response from KAS", VIRTRU_NETWORK_ERROR);
            }
            else{
                ThrowException("Could not parse KAS rewrap response: " + boost::current_exception_diagnostic_information() + "  with response: " + unwrapResponse, VIRTRU_NETWORK_ERROR);
            }
        }
        std::string entityWrappedKey = rewrappedObj[kEntityWrappedKey];
        auto entityWrappedKeyDecode = base64Decode(entityWrappedKey);

        auto decoder = AsymDecryption::create(m_tdfBuilder.m_impl->m_privateKey);

        std::vector<gsl::byte> outBuffer(decoder->getOutBufferSize());
        auto writeableBytes = toWriteableBytes(outBuffer);
        decoder->decrypt(toBytes(entityWrappedKeyDecode), writeableBytes);

        WrappedKey wrappedKey;
        std::copy(writeableBytes.begin(), writeableBytes.end(), wrappedKey.begin());

        return wrappedKey;
    }

    /// Return tdf zip data by parsing html tdf file.
    std::vector<std::uint8_t> TDFImpl::getTDFZipData(const std::string &htmlTDFFilepath,
                                                      bool manifestData) {
        LogTrace("TDFImpl::getTDFZipData file");

        /// Protocol is .html
        XMLDocFreePtr xmlDoc{htmlReadFile(htmlTDFFilepath.data(), nullptr,
                                          HTML_PARSE_RECOVER | HTML_PARSE_NOWARNING |
                                              HTML_PARSE_NOERROR | HTML_PARSE_NODEFDTD |
                                              HTML_PARSE_NONET | HTML_PARSE_NOIMPLIED)};

        if (!xmlDoc) {
            std::string errorMsg{"Failed to parse file - "};
            errorMsg.append(htmlTDFFilepath);
            ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
        }

        return getTDFZipData(std::move(xmlDoc), manifestData);
    }

    /// Return tdf zip data by parsing html tdf file.
    std::vector<std::uint8_t> TDFImpl::getTDFZipData(Bytes bytes, bool manifestData) {

        LogTrace("TDFImpl::getTDFZipData memory");

        XMLDocFreePtr xmlDoc{htmlReadMemory(reinterpret_cast<const char *>(bytes.data()), bytes.size(),
                                            nullptr, nullptr,
                                            HTML_PARSE_RECOVER | HTML_PARSE_NOWARNING |
                                                HTML_PARSE_NOERROR | HTML_PARSE_NODEFDTD |
                                                HTML_PARSE_NONET | HTML_PARSE_NOIMPLIED)};

        if (!xmlDoc) {
            ThrowException("Failed to parse file html payload", VIRTRU_TDF_FORMAT_ERROR);
        }

        return getTDFZipData(std::move(xmlDoc), manifestData);
    }

    /// Return tdf zip data from XMLDoc object.
    std::vector<std::uint8_t> TDFImpl::getTDFZipData(XMLDocFreePtr xmlDocPtr, bool manifestData) {

        LogTrace("TDFImpl::getTDFZipData xmlDoc");

        // Create xpath context
        XMLXPathContextFreePtr context{xmlXPathNewContext(xmlDocPtr.get())};
        if (!context) {
            ThrowException("Failed to create xmlXPathNewContext");
        }

        // Find the 'input' element with attribute 'id' = "data-input"
        const xmlChar *xpath = (xmlChar *)"//body/input";
        XMLXPathObjectFreePtr result{xmlXPathEvalExpression(xpath, context.get())};
        if (!result) {
            ThrowException("Fail to evaluate XPath expression", VIRTRU_TDF_FORMAT_ERROR);
        }

        if (xmlXPathNodeSetIsEmpty(result->nodesetval)) {
            ThrowException("<input> elements are missing", VIRTRU_TDF_FORMAT_ERROR);
        }

        XMLCharFreePtr xmlCharBase64TDF;
        xmlNodeSetPtr nodeset = result->nodesetval;
        for (int i = 0; i < nodeset->nodeNr; i++) {

            // input element.
            xmlNodePtr inputNode = nodeset->nodeTab[i];
            XMLCharFreePtr attributeValue{xmlGetProp(inputNode, reinterpret_cast<const xmlChar *>(kHTMLIdAttribute))};

            auto attributeValueType = kHTMLDataInput;
            if (manifestData) {
                attributeValueType = kHTMLDataManifest;
            }

            // Check for attributeType("data-input" or "data-manifest")
            if (attributeValue && boost::iequals(attributeValueType, reinterpret_cast<const char *>(attributeValue.get()))) {

                xmlChar *base64TDF = xmlGetProp(inputNode, reinterpret_cast<const xmlChar *>(kHTMLValueAttribute));
                if (!base64TDF) {
                    ThrowException("Value attribute is missing from html payload.", VIRTRU_TDF_FORMAT_ERROR);
                }
                xmlCharBase64TDF.reset(base64TDF);
                break;
            }
        }

        if (!xmlCharBase64TDF) {
            ThrowException("Value attribute is missing from html payload.", VIRTRU_TDF_FORMAT_ERROR);
        }

        // TODO: This is memory inefficent.
        auto base64TDFLength = xmlStrlen(xmlCharBase64TDF.get());
        std::vector<std::uint8_t> decodeBuffer(decoded_size(base64TDFLength));

        auto const decodeResult = decode(&decodeBuffer[0], reinterpret_cast<const char *>(xmlCharBase64TDF.get()), base64TDFLength);
        decodeBuffer.resize(decodeResult.first);

        return decodeBuffer;
    }

    // Return the TDF protocol used to encrypt the file
    Protocol TDFImpl::encryptedWithProtocol(const std::string& inTdfFilePath) {

        LogTrace("TDFImpl::encryptedWithProtocol file");

        // Open the input file for reading.
        std::ifstream inputStream{inTdfFilePath, std::ios_base::in | std::ios_base::binary};
        if (!inputStream) {
            std::string errorMsg{"Failed to open file for reading:"};
            errorMsg.append(inTdfFilePath);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }

        static constexpr auto twoChar = 2;

        // Read first 2 chars from file and determine the protocol
        std::vector<char> result(twoChar);
        inputStream.read(reinterpret_cast<char *>(result.data()), twoChar);

        if (boost::iequals(std::string(result.begin(), result.end()), firstTwoCharsOfZip)) {
            return Protocol::Zip;
        } else if(boost::iequals(std::string(result.begin(), result.end()), firstTwoCharsOfXML)) {
            return Protocol::Xml;
        } else {
            return Protocol::Html;
        }
    }

    // Return the TDF protocol used to encrypt the input stream data
    Protocol TDFImpl::encryptedWithProtocol(std::istream& tdfInStream) {

        LogTrace("TDFImpl::encryptedWithProtocol stream");

        static constexpr auto twoChar = 2;

        // set to the start.
        tdfInStream.seekg(0, tdfInStream.beg);

        // Read first 2 chars from file and determine the protocol
        std::vector<char> result(twoChar);
        tdfInStream.read(reinterpret_cast<char *>(result.data()), twoChar);

        Protocol protocol = Protocol::Html;
        if (boost::iequals(std::string(result.begin(), result.end()), firstTwoCharsOfZip)) {
            protocol = Protocol::Zip;
        } else if(boost::iequals(std::string(result.begin(), result.end()), firstTwoCharsOfXML)) {
            protocol = Protocol::Xml;
        }

        // Move back to the start.
        tdfInStream.seekg(0, tdfInStream.beg);

        return protocol;
    }

    /// Retrive the policy from the manifest.
    std::string TDFImpl::getPolicyFromManifest(const std::string &manifestStr) const {
        LogTrace("TDFImpl::getPolicyFromManifest");

        auto manifest = nlohmann::json::parse(manifestStr);

        if (!manifest.contains(kEncryptionInformation)) {
            std::string errorMsg{"'encryptionInformation' not found in the manifest of tdf."};
            ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
        }

        auto &encryptionInformation = manifest[kEncryptionInformation];

        if (!encryptionInformation.contains(kPolicy)) {
            std::string errorMsg{"'policy' not found in the manifest of tdf."};
            ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
        }

        // Get policy
        std::string base64Policy = encryptionInformation[kPolicy];
        auto policyStr = base64Decode(base64Policy);
        return policyStr;
    }

    /// Return the manifest from the tdf input stream.
    std::string TDFImpl::getManifest(std::istream &tdfInStream) const {
        LogTrace("TDFImpl::getManifest from tdf stream");

        // Reset the input stream.
        const auto final = gsl::finally([&tdfInStream] {
            tdfInStream.clear();
        });

        std::string manifestStr;

        auto protocol = encryptedWithProtocol(tdfInStream);
        if (protocol == Protocol::Zip) {
            TDFArchiveReader reader(tdfInStream, kTDFManifestFileName, kTDFPayloadFileName);

            manifestStr = reader.getManifest();
        } else { // html format

            if (protocol == Protocol::Xml) {
                ThrowException("XML TDF not supported", VIRTRU_TDF_FORMAT_ERROR);
            }

            // Get the stream size
            tdfInStream.seekg(0, tdfInStream.end);
            auto dataSize = tdfInStream.tellg();
            tdfInStream.seekg(0, tdfInStream.beg);

            std::unique_ptr<std::uint8_t[]> buffer(new std::uint8_t[dataSize]);

            // Read all the data from input stream
            tdfInStream.read(reinterpret_cast<char *>(buffer.get()), dataSize);

            auto bytes = gsl::make_span(buffer.get(), dataSize);
            auto manifestData = getTDFZipData(toBytes(bytes), true);

            manifestStr.append(manifestData.begin(), manifestData.end());
        }

        return manifestStr;
    }

    /// Retrive the policy uuid(id) from the manifest.
    std::string TDFImpl::getPolicyIdFromManifest(const std::string &manifestStr) const {
        auto policyStr = getPolicyFromManifest(manifestStr);
        auto policy = nlohmann::json::parse(policyStr);

        if (!policy.contains(kUid)) {
            std::string errorMsg{"'uuid' not found in the policy of tdf."};
            ThrowException(std::move(errorMsg), VIRTRU_TDF_FORMAT_ERROR);
        }

        return policy[kUid];
    }

    //============================================================

    std::string getManifest() {
        std::string result;
        return result;
    }

    std::vector<VBYTE> getFileSegment(const std::string &inFilepath, unsigned long segmentNumber) {
        LogTrace("TDFClient::getSegment");
        // open as zip
        // read 0.data
        // seek to requested segment
        // return requested segment number
        std::vector<VBYTE> result;
        return result;
    }

    unsigned long getSegmentCount(const std::string &inFilepath) {
        LogTrace("TDFClient::getSegmentCount");
        std::string manifest = getManifest();
        unsigned long result= 0;// = manifest.segmentCount;
        return result;
    }

    unsigned long getSegmentSize(const std::string &inFilepath) {
        LogTrace("TDFClient:getSegmentSize");
        std::string manifest = getManifest();
        unsigned long result = 0;// = manifest.segmentSize;
        return result;
    }

    void calculateSegmentRange(const std::string &inFilepath, size_t offset, size_t length, size_t* segmentOffset, size_t* segmentCount) {
        LogTrace("TDFClient::calculateSegmentRange");
        size_t segSize = getSegmentSize(inFilepath);
        *segmentOffset = offset % segSize;
        *segmentCount = (length % segSize) + 1;
    }


} // namespace virtru
