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
#include "file_io_provider.h"
#include "tdf_archive_writer.h"
#include "tdf_html_writer.h"
#include "stream_io_provider.h"
#include "rca_io_provider.h"
#include "benchmark.h"
#include "crypto/gcm_encryption.h"
#include "crypto/gcm_decryption.h"
#include "crypto/bytes.h"
#include "utils.h"

#include <memory>
#include <stdint.h>
#include <boost/algorithm/string.hpp>
#include <boost/beast/core/detail/base64.hpp>
#include <boost/interprocess/streams/bufferstream.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include <istream>
#include <fstream>
#include <jwt-cpp/jwt.h>
#include <memory>
#include <regex>
#include <streambuf>

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
    }

    /// Encrypt data from InputProvider and write to RCA OutputProvider
    std::string TDFImpl::encryptInputProviderToRCA(IInputProvider& inputProvider) {

        LogTrace("TDFImpl::encryptIOProviderImpl");

        auto dataSize = inputProvider.getSize();

        // Check if there is a policy object
        if (m_tdfBuilder.m_impl->m_policyObject.getUuid().empty()) {
            ThrowException("Policy object is missing.", VIRTRU_TDF_FORMAT_ERROR);
        }

        if (m_tdfBuilder.m_impl->m_policyObject.getDissems().empty() &&
            m_tdfBuilder.m_impl->m_policyObject.getAttributeObjects().empty()) {
            LogWarn(kEmptyPolicyMsg);
        }

        // For RCA override the m_payloadKey
        WrappedKey payloadKey = symmetricKey<kKeyLength>();
        std::vector<std::uint8_t> payloadKeyBuffer(kKeyLength);
        std::memcpy(payloadKeyBuffer.data(), payloadKey.data(), kKeyLength);
        m_tdfBuilder.overridePayloadKey(payloadKeyBuffer);

        /// Create a split key and the key access object based on access type.
        auto splitKey = SplitKey{m_tdfBuilder.m_impl->m_cipherType};
        if (m_tdfBuilder.m_impl->m_overridePayloadKey) {
            splitKey.setPayloadKey(m_tdfBuilder.m_impl->m_payloadKey);
        }

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
        /// Create buffers for reading from file and for performing encryption.
        /// These buffers will be reused.
        ///
        auto encryptedBufferSize = defaultSegmentSize + ivSize + kAesBlockSize;
        std::vector<char> readBuffer(defaultSegmentSize); // TODO: may want use gsl::byte instead of char
        std::vector<gsl::byte> encryptedBuffer(encryptedBufferSize);

        /// upsert
        auto upsertResponse = upsert(manifest);

        std::cout << "Response from KAS is:" << upsertResponse << std::endl;

        /// Generate kek = Kv(Kp) -> wrappedkey(payloadkey)
        auto base64KeK = generateKeK(splitKey.getPolicyKey(), m_tdfBuilder.m_impl->m_payloadKey);
        std::cout << "Size:" << base64KeK.size() << "Data:" << base64KeK << std::endl;

        nlohmann::json upsertResponseObj;
        try {
            upsertResponseObj = nlohmann::json::parse(upsertResponse);
        } catch (...) {
            if (upsertResponseObj == ""){
                ThrowException("No rewrap response from KAS", VIRTRU_NETWORK_ERROR);
            } else {
                ThrowException("Could not parse KAS rewrap response: " + boost::current_exception_diagnostic_information() + "  with response: " + upsertResponse, VIRTRU_NETWORK_ERROR);
            }
        }

        RCAOutputProvider s3op("https://api.develop.virtru.com/rca", m_tdfBuilder.m_impl->m_httpHeaders);
        TDFArchiveWriter writer{&s3op,
                                kTDFManifestFileName,
                                kTDFPayloadFileName};

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

        size_t index{};
        while (totalSegment != 0) {

            auto readSize = defaultSegmentSize;
            if ((dataSize - index) < defaultSegmentSize) {
                readSize = (dataSize - index);
            }

            // Read the file in 'defaultSegmentSize' chuck max
            auto bytes = toWriteableBytes(readBuffer);
            inputProvider.readBytes(index, readSize, bytes);

            // make sub span of 'defaultSegmentSize' or less
            auto readBufferAsBytes = toBytes(readBuffer);
            Bytes subSpanBuffer{readBufferAsBytes.data(), static_cast<std::ptrdiff_t>(readSize)};
            auto writeableBytes = toWriteableBytes(encryptedBuffer);

            // Encrypt the payload
            splitKey.encrypt(subSpanBuffer, writeableBytes);

            ///
            // Check if all the bytes are encrypted.
            ///
            auto encryptedSize =readSize + ivSize + kAesBlockSize;
            if (writeableBytes.size() != encryptedSize) {
                ThrowException("Encrypted buffer output is not correct!", VIRTRU_TDF_FORMAT_ERROR);
            }

            // Generate signature for the encrypted payload.
            auto payloadSigStr = getSignature(writeableBytes, splitKey, segIntegrityAlg);

            // Append the aggregate payload signature.
            aggregateHash.append(payloadSigStr);

            nlohmann::json segmentInfo;
            segmentInfo[kHash] = base64Encode(payloadSigStr);
            segmentInfo[kSegmentSize] = readSize;
            segmentInfo[kEncryptedSegmentSize] = encryptedSize;
            segmentInfos.emplace_back(segmentInfo);

            // write the encrypted data to tdf file.
            writer.appendPayload(writeableBytes);

            totalSegment--;
            index += readSize;
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
        writer.finish();

        std::cout << "Filename:" << s3op.remoteFileName() << std::endl;
        std::cout << "Response from upsert is:" << to_string(upsertResponseObj) << std::endl;

        auto &responseObj = upsertResponseObj.at(0);
        auto uuid = responseObj["uuid"];

        // Construct contract url
        std::string uuidStr = uuid;
        std::string contractUrl = "https://api-develop01.develop.virtru.com/acm/api/policies/";
        contractUrl += uuidStr;
        contractUrl += "/contract";

        // Construct downloadUrl
        std::string downloadUrl = "https://api-develop01.develop.virtru.com/encrypted-storage/";
        downloadUrl += s3op.remoteFileName();
        std::cout << "Download URL is:" << downloadUrl << std::endl;


        std::ostringstream rcaLink;

        rcaLink << "https://secure.develop.virtru.com/start/#v=4.0.0";
        rcaLink << "&pu=";
        rcaLink << Utils::urlEncode(contractUrl);
        rcaLink << "&wu=";
        rcaLink << Utils::urlEncode(downloadUrl);
        rcaLink << "&wk=";
        std::string kekStr = base64KeK;
        rcaLink << kekStr;
        rcaLink << "&al=AES-256-GCM";

        std::cout << "RCA link:" << rcaLink.str() << std::endl;

        nlohmann::json rcaInfo;
        rcaInfo["downloadUrl"] = downloadUrl;
        rcaInfo["kek"] = base64KeK;

        return to_string(rcaInfo);
    }

    /// Decrypt RCA to OutputProvider
    void TDFImpl::decryptRCAToOutputProvider(const std::string& downloadURL,
                                             const std::string& kek,
                                             IOutputProvider& outputProvider) {


        RCAInputProvider s3op(downloadURL);
        TDFArchiveReader reader{&s3op,
                                kTDFManifestFileName,
                                kTDFPayloadFileName};

        auto manifestStr = reader.getManifest();

        // Parse the manifest
        auto manifest = nlohmann::json::parse(manifestStr);

        // Validate the cipher type before creating a split key
        validateCipherType(manifest);

        WrappedKey wrappedKey = unwrapKey(manifest);
        WrappedKey actualWrappedKey;

        auto kekDecode = base64Decode(kek);
        auto data = toBytes(kekDecode);

        // Copy the auth tag from the data buffer.
        ByteArray<kAesBlockSize> tag;
        std::copy_n(data.last(kAesBlockSize).data(), kAesBlockSize, begin(tag));

        // Update the input buffer size after the auth tag is copied.
        auto inputSpan = data.first(data.size() - kAesBlockSize);
        auto symDecoder = GCMDecryption::create(toBytes(wrappedKey), inputSpan.first(kGcmIvSize));

        // Update the input buffer size after the IV is copied.
        inputSpan = inputSpan.subspan(kGcmIvSize);

        // decrypt
        auto writeableBytes = WriteableBytes(actualWrappedKey);
        symDecoder->decrypt(inputSpan, writeableBytes);
        auto authTag = WriteableBytes{tag};
        symDecoder->finish(authTag);

        LogDebug("Obtained the wrappedKey from manifest.");

        // Create a split key and the key access object based on access type.
        auto splitKey = SplitKey{CipherType::Aes256GCM};
        splitKey.setWrappedKey(actualWrappedKey);

        // Validate the root signature from the manifest.
        validateRootSignature(splitKey, manifest);

        auto &integrityInformation = manifest[kEncryptionInformation][kIntegrityInformation];
        size_t segmentSizeDefault = integrityInformation[kSegmentSizeDefault];
        size_t defaultEncryptedSegmentSize = integrityInformation[kEncryptedSegSizeDefault];

        auto ivSize = (m_tdfBuilder.m_impl->m_cipherType == CipherType::Aes256GCM) ? kGcmIvSize : kCbcIvSize;
        if (segmentSizeDefault != (defaultEncryptedSegmentSize - ((ivSize + kAesBlockSize)))) {
            ThrowException("EncryptedSegmentSizeDefault is missing in tdf", VIRTRU_TDF_FORMAT_ERROR);
        }

        const auto& segmentInfos = manifest[kEncryptionInformation][kIntegrityInformation][kSegments];

        ///
        /// Create buffers for reading from file and for performing decryption.
        /// These buffers will be reused.
        ///
        std::vector<gsl::byte> readBuffer(defaultEncryptedSegmentSize);
        std::vector<gsl::byte> decryptedBuffer(segmentSizeDefault);

        std::string segmentHashAlg = integrityInformation[kSegmentHashAlg];
        size_t payloadOffset = 0;
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
            reader.readPayload(payloadOffset, readBufferSpan.size(), readBufferSpan);
            payloadOffset += readBufferSpan.size();

            // Decrypt the payload.
            splitKey.decrypt(readBufferSpan, outBufferSpan);

            auto payloadSigStr = getSignature(readBufferSpan, splitKey, segmentHashAlg);
            std::string hash = segment[kHash];

            // Validate the hash.
            if (hash != base64Encode(payloadSigStr)) {
                ThrowException("Failed integrity check on segment hash", VIRTRU_CRYPTO_ERROR);
            }

            outputProvider.writeBytes(outBufferSpan);
        }
    }

    /// Encrypt data from InputProvider and write to IOutputProvider
    std::string TDFImpl::encryptIOProvider(IInputProvider& inputProvider,
                                           IOutputProvider& outputProvider) {

        if (m_tdfBuilder.m_impl->m_protocol == Protocol::Zip) {

            TDFArchiveWriter writer{&outputProvider,
                                    kTDFManifestFileName,
                                    kTDFPayloadFileName};

            auto response = encryptIOProviderImpl(inputProvider, writer);
            return response.second;
        } else if (m_tdfBuilder.m_impl->m_protocol == Protocol::Xml) {
            TDFXMLWriter writer{outputProvider,
                                kTDFManifestFileName,
                                kTDFPayloadFileName};

            auto response = encryptIOProviderImpl(inputProvider, writer);
            return response.second;
        } else { // HTML
            struct HTMLOutputProvider: IOutputProvider {
                void writeBytes(Bytes bytes) override {
                    stringStream.write(toChar(bytes.data()), bytes.size());
                }
                void flush() override { stringStream.flush(); }
                std::stringstream stringStream{};
            };

            HTMLOutputProvider htmlOutputProvider{};
            TDFArchiveWriter writer{&htmlOutputProvider,
                                    kTDFManifestFileName,
                                    kTDFPayloadFileName};
            auto response = encryptIOProviderImpl(inputProvider, writer);
            auto manifestStr = response.first;
            htmlOutputProvider.flush();
            generateHtmlTdf(manifestStr, htmlOutputProvider.stringStream, outputProvider);
            return response.second;
        }
    }

    /// Encrypt data from InputProvider and write to IOutputProvider
    std::pair<std::string, std::string> TDFImpl::encryptIOProviderImpl(IInputProvider& inputProvider,
                                                                       ITDFWriter& writer) {
        LogTrace("TDFImpl::encryptIOProviderImpl");


        auto dataSize = inputProvider.getSize();

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
        if (m_tdfBuilder.m_impl->m_overridePayloadKey) {
            splitKey.setPayloadKey(m_tdfBuilder.m_impl->m_payloadKey);
        }

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
        /// Create buffers for reading from file and for performing encryption.
        /// These buffers will be reused.
        ///
        auto encryptedBufferSize = defaultSegmentSize + ivSize + kAesBlockSize;
        std::vector<char> readBuffer(defaultSegmentSize); // TODO: may want use gsl::byte instead of char
        std::vector<gsl::byte> encryptedBuffer(encryptedBufferSize);

        /// upsert
        auto upsertResponse = upsert(manifest);

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

        size_t index{};
        while (totalSegment != 0) {

            auto readSize = defaultSegmentSize;
            if ((dataSize - index) < defaultSegmentSize) {
                readSize = (dataSize - index);
            }

            // Read the file in 'defaultSegmentSize' chuck max
            auto bytes = toWriteableBytes(readBuffer);
            inputProvider.readBytes(index, readSize, bytes);

            // make sub span of 'defaultSegmentSize' or less
            auto readBufferAsBytes = toBytes(readBuffer);
            Bytes subSpanBuffer{readBufferAsBytes.data(), static_cast<std::ptrdiff_t>(readSize)};
            auto writeableBytes = toWriteableBytes(encryptedBuffer);

            // Encrypt the payload
            splitKey.encrypt(subSpanBuffer, writeableBytes);

            ///
            // Check if all the bytes are encrypted.
            ///
            auto encryptedSize =readSize + ivSize + kAesBlockSize;
            if (writeableBytes.size() != encryptedSize) {
                ThrowException("Encrypted buffer output is not correct!", VIRTRU_TDF_FORMAT_ERROR);
            }

            // Generate signature for the encrypted payload.
            auto payloadSigStr = getSignature(writeableBytes, splitKey, segIntegrityAlg);

            // Append the aggregate payload signature.
            aggregateHash.append(payloadSigStr);

            nlohmann::json segmentInfo;
            segmentInfo[kHash] = base64Encode(payloadSigStr);
            segmentInfo[kSegmentSize] = readSize;
            segmentInfo[kEncryptedSegmentSize] = encryptedSize;
            segmentInfos.emplace_back(segmentInfo);

            // write the encrypted data to tdf file.
            writer.appendPayload(writeableBytes);

            totalSegment--;
            index += readSize;
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
        writer.finish();

        std::cout << "Response from upsert is:" << upsertResponse << std::endl;
        return std::make_pair(to_string(manifest), upsertResponse);
    }


    /// Decrypt data from InputProvider and write to IOutputProvider
    void TDFImpl::decryptIOProvider(IInputProvider& inputProvider,
                           IOutputProvider& outputProvider) {

        auto protocol = encryptedWithProtocol(inputProvider);
        if (protocol == Protocol::Zip) {
            TDFArchiveReader reader{&inputProvider,
                                    kTDFManifestFileName,
                                    kTDFPayloadFileName};
            decryptIOProviderImpl(reader, outputProvider);
        } else if (protocol == Protocol::Xml) {
            TDFXMLReader reader{inputProvider};
            decryptIOProviderImpl(reader, outputProvider);
        } else { // HTML

            /// TODO: Improve the memory effeciency for html parsing.
            auto dataSize = inputProvider.getSize();
            std::unique_ptr<std::uint8_t[]> buffer(new std::uint8_t[dataSize]);

            // Read all the data from input provider
            auto htmlBytes = gsl::make_span(buffer.get(), dataSize);
            auto writeableBytes = toWriteableBytes(htmlBytes);
            inputProvider.readBytes(0, dataSize, writeableBytes);

            auto bytes = gsl::make_span(buffer.get(), dataSize);
            auto tdfData = getTDFZipData(toBytes(bytes));

            std::string tdfString(tdfData.begin(), tdfData.end());
            std::istringstream inputStream(tdfString);
            StreamInputProvider ipProvider{inputStream};
            TDFArchiveReader reader{&ipProvider, kTDFManifestFileName, kTDFPayloadFileName };

            decryptIOProviderImpl(reader, outputProvider);
        }
    }

    /// Decrypt data from reader and write to IOutputProvider
    void TDFImpl::decryptIOProviderImpl(ITDFReader& reader, IOutputProvider& outputProvider) {

        auto manifestStr = reader.getManifest();

        // Parse the manifest
        auto manifest = nlohmann::json::parse(manifestStr);

        // Validate the cipher type before creating a split key
        validateCipherType(manifest);

        WrappedKey wrappedKey = unwrapKey(manifest);

        LogDebug("Obtained the wrappedKey from manifest.");

        // Create a split key and the key access object based on access type.
        auto splitKey = SplitKey{CipherType::Aes256GCM};
        splitKey.setWrappedKey(wrappedKey);

        // Validate the root signature from the manifest.
        validateRootSignature(splitKey, manifest);

        auto &integrityInformation = manifest[kEncryptionInformation][kIntegrityInformation];
        size_t segmentSizeDefault = integrityInformation[kSegmentSizeDefault];
        size_t defaultEncryptedSegmentSize = integrityInformation[kEncryptedSegSizeDefault];

        auto ivSize = (m_tdfBuilder.m_impl->m_cipherType == CipherType::Aes256GCM) ? kGcmIvSize : kCbcIvSize;
        if (segmentSizeDefault != (defaultEncryptedSegmentSize - ((ivSize + kAesBlockSize)))) {
            ThrowException("EncryptedSegmentSizeDefault is missing in tdf", VIRTRU_TDF_FORMAT_ERROR);
        }

        const auto& segmentInfos = manifest[kEncryptionInformation][kIntegrityInformation][kSegments];

        ///
        /// Create buffers for reading from file and for performing decryption.
        /// These buffers will be reused.
        ///
        std::vector<gsl::byte> readBuffer(defaultEncryptedSegmentSize);
        std::vector<gsl::byte> decryptedBuffer(segmentSizeDefault);

        std::string segmentHashAlg = integrityInformation[kSegmentHashAlg];
        size_t payloadOffset = 0;
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
            reader.readPayload(payloadOffset, readBufferSpan.size(), readBufferSpan);
            payloadOffset += readBufferSpan.size();

            // Decrypt the payload.
            splitKey.decrypt(readBufferSpan, outBufferSpan);

            auto payloadSigStr = getSignature(readBufferSpan, splitKey, segmentHashAlg);
            std::string hash = segment[kHash];

            // Validate the hash.
            if (hash != base64Encode(payloadSigStr)) {
                ThrowException("Failed integrity check on segment hash", VIRTRU_CRYPTO_ERROR);
            }

            outputProvider.writeBytes(outBufferSpan);
        }
    }

    /// Decrypt data starting at index and of length from input provider
    /// and write to output provider
    void TDFImpl::decryptIOProviderPartial(IInputProvider& inputProvider,
                                           IOutputProvider& outputProvider,
                                           size_t offset,
                                           size_t length) {

        auto protocol = encryptedWithProtocol(inputProvider);
        if (protocol != Protocol::Zip) {
            ThrowException("Only zip protocol is supported", VIRTRU_TDF_FORMAT_ERROR);
        }

        TDFArchiveReader reader{&inputProvider, kTDFManifestFileName, kTDFPayloadFileName };
        auto manifestStr = reader.getManifest();

        // Parse the manifest
        auto manifest = nlohmann::json::parse(manifestStr);

        // Validate the cipher type before creating a split key
        validateCipherType(manifest);

        WrappedKey wrappedKey = unwrapKey(manifest);

        LogDebug("Obtained the wrappedKey from manifest.");

        // Create a split key and the key access object based on access type.
        auto splitKey = SplitKey{CipherType::Aes256GCM};
        splitKey.setWrappedKey(wrappedKey);

        // Validate the root signature from the manifest.
        validateRootSignature(splitKey, manifest);

        auto &integrityInformation = manifest[kEncryptionInformation][kIntegrityInformation];
        size_t segmentSizeDefault = integrityInformation[kSegmentSizeDefault];
        size_t defaultEncryptedSegmentSize = integrityInformation[kEncryptedSegSizeDefault];

        auto ivSize = (m_tdfBuilder.m_impl->m_cipherType == CipherType::Aes256GCM) ? kGcmIvSize : kCbcIvSize;
        if (segmentSizeDefault != (defaultEncryptedSegmentSize - ((ivSize + kAesBlockSize)))) {
            ThrowException("EncryptedSegmentSizeDefault is missing in tdf", VIRTRU_TDF_FORMAT_ERROR);
        }

        // Get the segments array and calculate the payload size.
        const auto& segmentInfos = manifest[kEncryptionInformation][kIntegrityInformation][kSegments];
        auto segmentArraySize = segmentInfos.size();
        size_t encryptedPayloadSize = 0;
        for (const auto& segment : segmentInfos) {
            size_t encryptedSegmentSize = segment[kEncryptedSegmentSize];
            encryptedPayloadSize += encryptedSegmentSize;
        }

        auto payloadSize = encryptedPayloadSize - (segmentArraySize * (ivSize + kAesBlockSize));
        auto segmentOffset = static_cast<size_t>((floor(static_cast<double>(offset)/static_cast<double>(segmentSizeDefault))));
        auto lastSegment = static_cast<size_t>(ceil(static_cast<double>(offset+length)/static_cast<double>(segmentSizeDefault)));

        if (segmentOffset >= lastSegment) {
            ThrowException("Fail to calculate the required segments", VIRTRU_TDF_FORMAT_ERROR);
        }

        if ((offset + length) > payloadSize) {
            ThrowException("Fail to calculate the required segments", VIRTRU_TDF_FORMAT_ERROR);
        }

        auto sizeRequiredForSegments = segmentSizeDefault * ((lastSegment - segmentOffset) + 1);
        std::vector<gsl::byte> bufferForRequiredSegments(sizeRequiredForSegments);
        auto bufferOffset = 0;

        ///
        /// Create buffers for reading from file and for performing decryption.
        /// These buffers will be reused.
        ///
        std::vector<gsl::byte> readBuffer(defaultEncryptedSegmentSize);
        std::vector<gsl::byte> decryptedBuffer(segmentSizeDefault);
        std::string segmentHashAlg = integrityInformation[kSegmentHashAlg];

        size_t payloadOffset = 0;
        for (size_t index = 0; index < segmentInfos.size(); index++) {

            const auto& segment = segmentInfos[index];

            size_t encryptedSegmentSize = segment[kEncryptedSegmentSize];
            if (segmentOffset > index ) {
                // Update the payload offset and skip the read.
                payloadOffset += encryptedSegmentSize;
                continue;
            } else {

                // Adjust read buffer size
                auto readBufferSpan = WriteableBytes{readBuffer};
                if (segment.contains(kEncryptedSegmentSize)) {
                    readBufferSpan = WriteableBytes{readBufferSpan.data(),
                                                    static_cast<std::ptrdiff_t>(encryptedSegmentSize)};
                }

                // Adjust decrypt buffer size
                auto outBufferSpan = WriteableBytes{decryptedBuffer};
                if (segment.contains(kSegmentSize)) {
                    int segmentSize = segment[kSegmentSize];
                    outBufferSpan = WriteableBytes{outBufferSpan.data(), segmentSize};
                }


                // Read form zip reader.
                reader.readPayload(payloadOffset, encryptedSegmentSize, readBufferSpan);
                payloadOffset += encryptedSegmentSize;

                // Decrypt the payload.
                splitKey.decrypt(readBufferSpan, outBufferSpan);

                auto payloadSigStr = getSignature(readBufferSpan, splitKey, segmentHashAlg);
                std::string hash = segment[kHash];

                // Validate the hash.
                if (hash != base64Encode(payloadSigStr)) {
                    ThrowException("Failed integrity check on segment hash", VIRTRU_CRYPTO_ERROR);
                }

                // Write the decrypted data to segment buffer
                std::copy(outBufferSpan.begin(),
                          outBufferSpan.end(),
                          bufferForRequiredSegments.begin() + bufferOffset);
                bufferOffset += outBufferSpan.size();
            }

            if (index == lastSegment) {
                break;
            }
        }

        size_t startOfPlainText = offset - (segmentOffset * segmentSizeDefault);
        auto bytesToWrite = gsl::make_span(reinterpret_cast<const char *>(bufferForRequiredSegments.data() + startOfPlainText),
                                           length);
        outputProvider.writeBytes(toBytes(bytesToWrite));
    }

    bool TDFImpl::isInputProviderTDF(IInputProvider& inputProvider) {
        LogTrace("TDFImpl::isInputProviderTDF");

        auto protocol = encryptedWithProtocol(inputProvider);
        try
        {
            if (protocol == Protocol::Zip) {
                TDFArchiveReader reader{&inputProvider, kTDFManifestFileName, kTDFPayloadFileName };
                reader.getManifest();
                return true;

            } else if (protocol == Protocol::Xml) {
                TDFXMLReader reader{inputProvider};
                reader.getManifest();
                reader.getPayloadSize();
                return true;
            } else {
                auto dataSize = inputProvider.getSize();
                std::unique_ptr<std::uint8_t[]> buffer(new std::uint8_t[dataSize]);

                // Read all the data from input stream
                auto htmlBytes = gsl::make_span(buffer.get(), dataSize);
                auto writeableBytes = toWriteableBytes(htmlBytes);
                inputProvider.readBytes(0, dataSize, writeableBytes);

                auto bytes = gsl::make_span(buffer.get(), dataSize);
                auto tdfData = getTDFZipData(toBytes(bytes));
                auto manifestData = getTDFZipData(toBytes(bytes), true);

                std::string tdfString(tdfData.begin(), tdfData.end());
                std::istringstream inputStream(tdfString);
                StreamInputProvider ipProvider{inputStream};
                TDFArchiveReader reader{&ipProvider, kTDFManifestFileName, kTDFPayloadFileName };
                reader.getManifest();
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
    std::string TDFImpl::getEncryptedMetadata(IInputProvider& inputProvider) {
        LogTrace("TDFImpl::getEncryptedMetadata");

        auto manifestStr = getManifest(inputProvider);
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

    /// Extract and return the JSON policy string from the input provider.
    std::string TDFImpl::getPolicy(IInputProvider& inputProvider) {

        LogTrace("TDFImpl::getPolicy");

        auto manifestStr = getManifest(inputProvider);
        return getPolicyFromManifest(manifestStr);
    }

    /// Return the policy uuid from the input provider.
    std::string TDFImpl::getPolicyUUID(IInputProvider& inputProvider) {

        LogTrace("TDFImpl::getPolicyUUID");

        std::string manifestStr = getManifest(inputProvider);
        return getPolicyIdFromManifest(manifestStr);
    }

    /// Sync the tdf file, with symmetric wrapped key and Policy Object.
    void TDFImpl::sync(const std::string &encryptedTdfFilepath) const {

        LogTrace("TDFImpl::sync");

        std::string manifestStr;

        FileInputProvider inputProvider{encryptedTdfFilepath};
        auto protocol = encryptedWithProtocol(inputProvider);
        if (protocol == Protocol::Zip) {
            // Open the input file for reading.
            std::ifstream inputStream{encryptedTdfFilepath, std::ios_base::in | std::ios_base::binary};
            if (!inputStream) {
                std::string errorMsg{"Failed to open file for reading:"};
                errorMsg.append(encryptedTdfFilepath);
                ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
            }

            TDFArchiveReader reader{&inputProvider,
                                    kTDFManifestFileName,
                                    kTDFPayloadFileName};
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

            return hexHmacSha256(payload, splitkey.getPayloadKey());

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
    std::string TDFImpl::upsert(nlohmann::json &manifest, bool ignoreKeyAccessType) const {

        LogTrace("TDFImpl::upsert");

        if (!ignoreKeyAccessType && m_tdfBuilder.m_impl->m_keyAccessType == KeyAccessType::Wrapped) {
            LogDebug("Bypass upsert for wrapped key type.");
            return {};
        }

        Benchmark benchmark("Upsert");

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

        return upsertResponse;
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

        Benchmark benchmark("Unwrap");
        LogTrace("TDFImpl::unwrapKey");

        nlohmann::json keyAccessObjects = nlohmann::json::array();
        keyAccessObjects = manifest[kEncryptionInformation][kKeyAccess];
        if (keyAccessObjects.size() != 1) {
            ThrowException("Only supports one key access object - unwrap", VIRTRU_TDF_FORMAT_ERROR);
        }

        // First object
        auto &keyAccess = keyAccessObjects.at(0);
        auto keyAccessObject = KeyAccessObject::createKeyAccessObjectFromJson(to_string(keyAccess));
        auto kasUrlFromTDF = keyAccessObject.getKasUrl();

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
            rewrapUrl = kasUrlFromTDF + kRewrapV2;
        } else {
            buildRewrapV1Payload(requestBody);
            requestBodyStr = to_string(requestBody);
            rewrapUrl = kasUrlFromTDF + kRewrap;
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

        auto headers = m_tdfBuilder.m_impl->m_httpHeaders;
        if (m_tdfBuilder.m_impl->m_overridePayloadKey) {
            auto base64PubKey = base64Encode(m_tdfBuilder.m_impl->m_publicKey);
            headers[kVirtruPublicKey] =base64PubKey;
        }

        sp->executePost(rewrapUrl, headers, std::move(requestBodyStr),
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

    void TDFImpl::generateHtmlTdf(const std::string &manifest,
                                  std::istream &inputStream,
                                  IOutputProvider& outputProvider) {

        LogTrace("TDFImpl::generateHtmlTdf");

        using namespace boost::beast::detail::base64;

        auto const &token1 = m_tdfBuilder.m_impl->m_htmlTemplateTokens[0];
        LogTrace("before token1 write");
        outputProvider.writeBytes(toBytes(token1));

        /// 1 - Write the contents of the tdf in base64
        std::size_t actualEncodedBufSize;
        std::vector<std::uint8_t> zipReadBuffer(kZipReadSize);
        std::vector<std::uint8_t> encodeBuffer(encoded_size(kZipReadSize));

        // Vectors m_encodeBufferSize and m_zipReadBuffer are sized in constructor if protocol is html
        while (!inputStream.eof()) {

            // Read from the file.
            LogTrace("before zip read");
            inputStream.read(reinterpret_cast<char *>(zipReadBuffer.data()), kZipReadSize);

            // Encode the tdf zip data.
            actualEncodedBufSize = encode(encodeBuffer.data(), zipReadBuffer.data(), inputStream.gcount());

            // Write to the html file
            LogTrace("before encoded data write");
            auto bytes = gsl::make_span(encodeBuffer.data(), actualEncodedBufSize);
            outputProvider.writeBytes(toBytes(bytes));
        }

        auto const &token2 = m_tdfBuilder.m_impl->m_htmlTemplateTokens[1];
        LogTrace("before token1 write");
        outputProvider.writeBytes(toBytes(token2));

        /// 2 - Write the contents of the manifest in base64

        // manifest can grow larger than our prealloc'ed buffer, correct that if it's a problem
        unsigned manifestEncodedSize = encoded_size(manifest.size());
        if (manifestEncodedSize > encodeBuffer.size()) {
            encodeBuffer.resize(manifestEncodedSize);
        }
        actualEncodedBufSize = encode(encodeBuffer.data(), manifest.data(), manifest.size());
        LogTrace("before manifest write");

        auto bytes = gsl::make_span(encodeBuffer.data(), actualEncodedBufSize);
        outputProvider.writeBytes(toBytes(bytes));

        auto const &token3 = m_tdfBuilder.m_impl->m_htmlTemplateTokens[2];
        LogTrace("before token3 write");
        outputProvider.writeBytes(toBytes(token3));

        /// 3 - Write the secure reader url.
        const auto &url = m_tdfBuilder.m_impl->m_secureReaderUrl;
        LogTrace("before sr url write");
        outputProvider.writeBytes(toBytes(url));

        auto const &token4 = m_tdfBuilder.m_impl->m_htmlTemplateTokens[3];
        LogTrace("before token4 write");
        outputProvider.writeBytes(toBytes(token4));

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
        outputProvider.writeBytes(toBytes(targetBaseUrlStr));

        auto const &token5 = m_tdfBuilder.m_impl->m_htmlTemplateTokens[4];
        LogTrace("before token5 write");
        outputProvider.writeBytes(toBytes(token5));

        /// 5 - Write he secure reader url for window.location.href - 1
        LogTrace("before sr url write 2");
        outputProvider.writeBytes(toBytes(url));

        auto const &token6 = m_tdfBuilder.m_impl->m_htmlTemplateTokens[5];
        LogTrace("before token6 write");
        outputProvider.writeBytes(toBytes(token6));

        /// 6 - Write he secure reader url for window.location.href - 2
        LogTrace("before sr url write 2");
        outputProvider.writeBytes(toBytes(url));

        auto const &token7 = m_tdfBuilder.m_impl->m_htmlTemplateTokens[6];
        LogTrace("before token7 write");
        outputProvider.writeBytes(toBytes(token7));

        LogTrace("exiting TDFImpl::generateHtmlTdf");
    }


    /// Return the TDF protocol used to encrypt the data from input provider
    Protocol TDFImpl::encryptedWithProtocol(IInputProvider& inputProvider) {

        LogTrace("TDFImpl::encryptedWithProtocol input provider");

        static constexpr auto twoChar = 2;
        std::vector<char> result(twoChar);

        // Read first 2 chars from file and determine the protocol
        auto resultBytes = toWriteableBytes(result);
        inputProvider.readBytes(0, twoChar, resultBytes);

        Protocol protocol = Protocol::Html;
        if (boost::iequals(std::string(result.begin(), result.end()), firstTwoCharsOfZip)) {
            protocol = Protocol::Zip;
        } else if(boost::iequals(std::string(result.begin(), result.end()), firstTwoCharsOfXML)) {
            protocol = Protocol::Xml;
        }

        return protocol;
    }

    /// Return the manifest from the tdf input provider.
    std::string TDFImpl::getManifest(IInputProvider& inputProvider) const {
        LogTrace("TDFImpl::getManifest from tdf stream");

        std::string manifestStr;

        auto protocol = encryptedWithProtocol(inputProvider);
        if (protocol == Protocol::Zip) {
            TDFArchiveReader reader{&inputProvider,
                                    kTDFManifestFileName,
                                    kTDFPayloadFileName};
            manifestStr = reader.getManifest();
        } else { // html format

            if (protocol == Protocol::Xml) {
                ThrowException("XML TDF not supported", VIRTRU_TDF_FORMAT_ERROR);
            }

            auto dataSize = inputProvider.getSize();
            std::unique_ptr<std::uint8_t[]> buffer(new std::uint8_t[dataSize]);

            // Read all the data from input stream
            auto htmlBytes = gsl::make_span(buffer.get(), dataSize);
            auto writeableBytes = toWriteableBytes(htmlBytes);
            inputProvider.readBytes(0, dataSize, writeableBytes);

            auto bytes = gsl::make_span(buffer.get(), dataSize);
            auto manifestData = getTDFZipData(toBytes(bytes), true);

            manifestStr.append(manifestData.begin(), manifestData.end());
        }

        return manifestStr;
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

    /// Validate the supported cipher type
    void TDFImpl::validateCipherType(const nlohmann::json& manifest) const {
        // Get the algorithm and key type.
        std::string algorithm = manifest[kEncryptionInformation][kMethod][kCipherAlgorithm];
        std::string keyType = manifest[kEncryptionInformation][kEncryptKeyType];

        if (!boost::iequals(algorithm, kCipherAlgorithmGCM)) {
            ThrowException("Only AES GCM cipher algorithm is supported for tdf operations.", VIRTRU_CRYPTO_ERROR);
        }

        if (!boost::iequals(keyType, kSplitKeyType)) {
            ThrowException("Only split key type is supported for tdf operations.", VIRTRU_CRYPTO_ERROR);
        }
    }

    /// Validate the root signature.
    void TDFImpl::validateRootSignature(SplitKey& splitKey, const nlohmann::json& manifest) const {

        auto &rootSignature = manifest[kEncryptionInformation][kIntegrityInformation][kRootSignature];
        std::string rootSignatureAlg = rootSignature[kRootSignatureAlg];
        std::string rootSignatureSig = rootSignature[kRootSignatureSig];

        // Get the hashes from the segments and combine.
        std::string aggregateHash;
        const auto&  segmentInfos= manifest[kEncryptionInformation][kIntegrityInformation][kSegments];
        for (const auto& segment : segmentInfos) {
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

        // Check for default encrypted segment size.
        if (!integrityInformation.contains(kEncryptedSegSizeDefault)) {
            ThrowException("EncryptedSegmentSizeDefault is missing in tdf", VIRTRU_TDF_FORMAT_ERROR);
        }
    }

    /// Generate a KeK for RCA. Kek -> policyKey(payloadKey)
    std::string TDFImpl::generateKeK(Bytes policyKey, Bytes payloadKey) const {

        ByteArray<kGcmIvSize> iv = symmetricKey<kGcmIvSize>();
        auto encryptBufferSize = iv.size() + payloadKey.size() +  kAesBlockSize;
        long finalSize =  encryptBufferSize;

        ByteArray<kAesBlockSize> tag;
        std::vector<gsl::byte> encryptedData(encryptBufferSize);
        auto writeableBytes = WriteableBytes{encryptedData};
        const auto bufferSpan = writeableBytes;

        auto encryptedDataSize = 0;
        const auto final = finalizeSize(writeableBytes, encryptedDataSize);

        // Adjust the span to add the IV vector at the start of the buffer
        auto encryptBufferSpan = bufferSpan.subspan(kGcmIvSize);

        auto encoder = GCMEncryption::create(policyKey, iv);
        encoder->encrypt(payloadKey, encryptBufferSpan);
        auto authTag = WriteableBytes{tag};
        encoder->finish(authTag);

        // Copy IV at start
        std::copy(iv.begin(), iv.end(), encryptedData.begin());

        // Copy tag at end
        std::copy(tag.begin(), tag.end(), encryptedData.begin() + kGcmIvSize + payloadKey.size());

        // Final size.
        encryptedDataSize = finalSize;

        auto kek =  base64Encode(toBytes(encryptedData));

        auto encryptedKek = base64Decode(toBytes(kek));
        std::cout<< "Size of decoded base64:" << encryptedKek.size() << std::endl;

        return kek;
    }

} // namespace virtrug
