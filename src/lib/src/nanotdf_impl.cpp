/*
* Copyright 2020 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/06/02
//

#include <boost/endian/arithmetic.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include <fstream>
#include <iostream>
#include "nlohmann/json.hpp"
#include <jwt-cpp/jwt.h>


#include "nanotdf/resource_locator.h"
#include "nanotdf/ecc_mode.h"
#include "nanotdf/symmetric_and_payload_config.h"
#include "nanotdf/policy_info.h"
#include "nanotdf_builder.h"
#include "nanotdf_builder_impl.h"
#include "crypto/gcm_encryption.h"
#include "crypto/gcm_decryption.h"
#include "crypto/ec_key_pair.h"
#include "sdk_constants.h"
#include "network/http_client_service.h"
#include "network/network_util.h"
#include "nanotdf_impl.h"
#include "benchmark.h"

#define DEBUG_LOG 0

namespace virtru {

    /// Constants
    constexpr auto kMaxTDFSize = ((16 * 1024 * 1024) - 3 - 32); // 16 mb - 3(iv) - 32(max auth tag)
    constexpr size_t kDatsetMaxMBBytes = 2097152; // 2mb
    // Max size of the encrypted tdfs
    //  16mb payload
    // ~67kb of policy
    // 133 of signature
    constexpr size_t kMaxEncryptedNTDFSize = (16 * 1024 * 1024) + (68 * 1024) + 133;
    constexpr auto kIvPadding = 9;

    /// namespace
    using namespace virtru::nanotdf;
    using namespace virtru::crypto;
    using namespace virtru::network;

    //
    /// Constructor
    NanoTDFImpl::NanoTDFImpl(NanoTDFBuilder& nanoTdfBuilder, bool datasetMode, std::uint32_t maxKeyIterations)
            : m_tdfBuilder(nanoTdfBuilder),
            m_datasetMode(datasetMode),
            m_maxKeyIterations(maxKeyIterations) {
        m_defaultSalt = calculateSHA256(toBytes(kNanoTDFMagicStringAndVersion));
    }

    /// Destructor
    NanoTDFImpl::~NanoTDFImpl() = default;

    /// Encrypt the file to nano tdf format.
    void NanoTDFImpl::encryptFile(const std::string& inFilepath, const std::string& outFilepath) {

        std::ifstream inStream( inFilepath, std::ios::binary | std::ios::ate);
        if (!inStream) {
            std::string errorMsg{"Failed to open file for reading - "};
            errorMsg.append(inFilepath);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }

        size_t fileSize = inStream.tellg();
        if (didExceedMaxSize(inStream.tellg())) {
            std::string errorMsg{"Data size not supported for NanoTDF - "};
            errorMsg.append(std::to_string(fileSize));
            ThrowException(std::move(errorMsg), VIRTRU_NANO_TDF_FORMAT_ERROR);
        }

        std::string_view outBuffer;
        if (fileSize == 0) {
            std::string emptyString;
            outBuffer = encryptString(toBytes(emptyString));
        } else {

            inStream.seekg(0, std::ios::beg);
            std::vector<char> fileContent(fileSize);
            inStream.read(fileContent.data(), fileSize);

            std::string_view buffer{fileContent.data(), fileSize};
            outBuffer = encryptString(toBytes(buffer));
        }

        // Open the tdf output file.
        std::ofstream outStream {outFilepath, std::ios_base::out | std::ios_base::binary};
        if (!outStream) {
            std::string errorMsg{"Failed to open file for writing:"};
            errorMsg.append(outFilepath);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }

        outStream.write(outBuffer.data(), outBuffer.size());
    }

    /// Encrypt the data to nano tdf format.
    std::string_view NanoTDFImpl::encryptString(Bytes plainData) {

        if (!plainData.data()) {
            std::string emptyString{};
            plainData = toBytes(emptyString);
        }

        if (m_tdfBuilder.m_impl->m_policyObject.getDissems().empty() &&
            m_tdfBuilder.m_impl->m_policyObject.getAttributeObjects().empty()) {
            LogWarn(kEmptyPolicyMsg);
        }

        auto exceedSize = didExceedMaxSize(plainData.size());
        if (exceedSize) {
            std::string errorMsg{"Data size not supported for NanoTDF - "};
            errorMsg.append(std::to_string(plainData.size()));
            ThrowException(std::move(errorMsg), VIRTRU_NANO_TDF_FORMAT_ERROR);
        }

        /// Resize the encrypt buffer only if needed.
        std::size_t requiredSize = plainData.size() + KNanoTDFOverhead;
        if (m_encryptBuffer.size() < requiredSize) {
            m_encryptBuffer.resize(requiredSize);
        }

        /// Resize the working buffer only if needed.
        auto authTagSize = SymmetricAndPayloadConfig::SizeOfAuthTagForCipher(m_tdfBuilder.m_impl->m_cipher);
        std::size_t sizeOfWorkingBuffer = kIvPadding + kNanoTDFIvSize + plainData.size() + authTagSize;
        if (m_workingBuffer.size() < sizeOfWorkingBuffer) {
            m_workingBuffer.resize(sizeOfWorkingBuffer);
        }

        std::uint32_t bytesAdded = 0;
        auto encryptBuffer = toWriteableBytes(m_encryptBuffer);

        // Create header
        createHeader(m_header);

        // Append the header to encrypt buffer.
        auto lengthOfHeader = m_header.writeIntoBuffer(toWriteableBytes(m_encryptBuffer));

        // Adjust the buffer
        bytesAdded += lengthOfHeader;
        encryptBuffer = encryptBuffer.subspan(bytesAdded);

        ///
        /// Add the length of cipher text to encrypt buffer - (IV + Cipher Text + Auth tag)
        ///
        std::uint32_t encryptedDataSize = kNanoTDFIvSize + plainData.size() + authTagSize;
        boost::endian::big_uint24_t cipherTextSize = encryptedDataSize;
        std::memcpy(encryptBuffer.data(), &cipherTextSize, sizeof(cipherTextSize));

        // Adjust the encrypt buffer
        bytesAdded += sizeof(cipherTextSize);
        encryptBuffer = encryptBuffer.subspan(sizeof(cipherTextSize));

        static_assert(sizeof(cipherTextSize) == 3u);

        std::array<gsl::byte, 32u> digest{};
        auto payloadBuffer = toWriteableBytes(m_workingBuffer);

        // Encrypt the payload into the working buffer
        {
            constexpr auto ivSizeWithPadding = kIvPadding + kNanoTDFIvSize;
            std::array<gsl::byte, ivSizeWithPadding> iv{};

            // Reset the IV after max iterations
            if (m_maxKeyIterations == m_keyIterationCount) {

                m_iv = 1;

                if (m_datasetMode) {
                    m_keyIterationCount = 0;
                }
            }

            auto ivBufferSpan = toWriteableBytes(iv).last(kNanoTDFIvSize);
            boost::endian::big_uint24_t ivAsNetworkOrder = m_iv;
            std::memcpy(ivBufferSpan.data(), &ivAsNetworkOrder, kNanoTDFIvSize);
            m_iv += 1;

            // Resize the auth tag.
            m_authTag.resize(authTagSize);

            // Adjust the span to add the IV vector at the start of the buffer after the encryption.
            auto payloadBufferSpan = payloadBuffer.subspan(ivSizeWithPadding);

            auto encoder = GCMEncryption::create(toBytes(m_encryptSymmetricKey), iv);
            encoder->encrypt(toBytes(plainData), payloadBufferSpan);

            auto authTag = WriteableBytes{m_authTag};
            encoder->finish(authTag);

            // Copy IV at start
            std::copy(iv.begin(), iv.end(), payloadBuffer.begin());

            // Copy tag at end
            std::copy(m_authTag.begin(), m_authTag.end(),
                      payloadBuffer.begin() + ivSizeWithPadding + plainData.size());
        }

        // Copy the payload buffer contents into encrypt buffer without the IV padding.
        std::copy(m_workingBuffer.begin() + kIvPadding, m_workingBuffer.end(),
                  encryptBuffer.begin());

        // Adjust the buffer
        bytesAdded += encryptedDataSize;
        encryptBuffer = encryptBuffer.subspan(encryptedDataSize);

        // Digest(header + payload) for signature
        digest = calculateSHA256({m_encryptBuffer.data(), static_cast<gsl::span<const std::byte,-1>::index_type>(bytesAdded)});

#if DEBUG_LOG
        auto digestData = base64Encode(toBytes(digest));
        std::cout << "Encrypt digest: " << digestData << std::endl;
#endif

        if (m_tdfBuilder.m_impl->m_hasSignature) {
            const auto& signerPrivateKey = m_tdfBuilder.m_impl->m_signerPrivateKey;
            auto curveName = ECCMode::GetEllipticCurveName(m_tdfBuilder.m_impl->m_signatureECCMode);
            auto signerPublicKey = ECKeyPair::GetPEMPublicKeyFromPrivateKey(signerPrivateKey, curveName);
            auto compressedPubKey = ECKeyPair::CompressedECPublicKey(signerPublicKey);

            // Add the signer public key
            std::memcpy(encryptBuffer.data(), compressedPubKey.data(), compressedPubKey.size());

#if DEBUG_LOG
            auto signerData = base64Encode(toBytes(compressedPubKey));
            std::cout << "Encrypt signer public key: " << signerData << std::endl;
#endif
            // Adjust the buffer
            bytesAdded += compressedPubKey.size();
            encryptBuffer = encryptBuffer.subspan(compressedPubKey.size());

            // Calculate the signature.
            m_signature = ECKeyPair::ComputeECDSASig(toBytes(digest), signerPrivateKey);
#if DEBUG_LOG
            auto sigData = base64Encode(toBytes(m_signature));
            std::cout << "Encrypt signature: " << sigData << std::endl;
#endif

            // Add the signature and update the count of bytes added.
            std::memcpy(encryptBuffer.data(), m_signature.data(), m_signature.size());

            // Adjust the buffer
            bytesAdded += m_signature.size();
        }

        if (m_datasetMode) {
            m_keyIterationCount += 1;
        }

        return { reinterpret_cast<const char*>(m_encryptBuffer.data()), bytesAdded};
    }

    /// Decrypt file the nano tdf file.
    void NanoTDFImpl::decryptFile(const std::string& inFilepath, const std::string& outFilepath) {

        std::ifstream inStream( inFilepath, std::ios::binary | std::ios::ate);
        if (!inStream) {
            std::string errorMsg{"Failed to open file for reading - "};
            errorMsg.append(inFilepath);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }

        size_t fileSize = inStream.tellg();
        if (fileSize > kMaxEncryptedNTDFSize || fileSize == 0) {
            std::string errorMsg{"Data size not supported for NanoTDF - "};
            errorMsg.append(std::to_string(fileSize));
            ThrowException(std::move(errorMsg), VIRTRU_NANO_TDF_FORMAT_ERROR);
        }

        inStream.seekg(0, std::ios::beg);
        std::vector<char> fileContent(fileSize);
        inStream.read(fileContent.data(), fileSize);
        
        std::string_view buffer{fileContent.data(), fileSize};
        auto outBuffer = decryptString(toBytes(buffer));

        // Open the tdf output file.
        std::ofstream outStream {outFilepath, std::ios_base::out | std::ios_base::binary};
        if (!outStream) {
            std::string errorMsg{"Failed to open file for writing:"};
            errorMsg.append(outFilepath);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }

        outStream.write(outBuffer.data(), outBuffer.size());
    }

    /// Decrypt data from nano tdf format.
    std::string_view NanoTDFImpl::decryptString(Bytes encryptedData) {

        auto startPoint = encryptedData.data();
        uint32_t bytesRead = 0;

        // Read the header.
        Header header{encryptedData};
        m_header = std::move(header);
        auto headerSize = m_header.getTotalSize();
        bytesRead += headerSize;

        // Adjust the buffer
        encryptedData = encryptedData.subspan(headerSize);

        if (m_tdfBuilder.m_impl->m_offlineMode) {
            // Generate the symmetric key.
            m_decryptSymmetricKey = generateSymmetricKey(m_header);
        } else {
            // Get the symmetric key from KAS
            m_decryptSymmetricKey = getSymmetricKey(m_header);
        }

        // Get the payload config.
        auto payloadConfig = m_header.getPayloadConfig();
        auto sizeOfAuthTag = SymmetricAndPayloadConfig::SizeOfAuthTagForCipher(payloadConfig.getCipherType());

        ///
        /// Read the length of cipher text to encrypt buffer - (IV + Cipher Text + Auth tag)
        ///
        constexpr auto bytesForCipherText = 3u;
        static_assert(sizeof(boost::endian::big_uint24_t) == bytesForCipherText);
        boost::endian::big_uint24_t bgCipherTextSize{0};
        std::memcpy(&bgCipherTextSize, encryptedData.data(), sizeof(boost::endian::big_uint24_t));
        std::uint32_t cipherTextSize = bgCipherTextSize;

        // Add total bytes occupied to store length of payload
        bytesRead += sizeof(boost::endian::big_uint24_t);

        // Adjust the size of decrypt buffer if needed.
        auto sizeOfPlainText = cipherTextSize - kNanoTDFIvSize - sizeOfAuthTag;
        if (m_decryptBuffer.size() < sizeOfPlainText) {
            m_decryptBuffer.resize(sizeOfPlainText);
        }

        // Adjust the buffer
        encryptedData = encryptedData.subspan(bytesForCipherText);
        { // Decrypt the payload

            m_authTag.resize(sizeOfAuthTag);

            auto data = gsl::make_span(encryptedData.data(), cipherTextSize);

            // Copy the auth tag from the data buffer.
            std::copy_n(data.last(sizeOfAuthTag).data(), sizeOfAuthTag, begin(m_authTag));

            // Update the input buffer size after the auth tag is copied.
            auto inputSpan = data.first(data.size() - sizeOfAuthTag);
            auto ivSpan = inputSpan.first(kNanoTDFIvSize);

            std::unique_ptr<GCMDecryption> decoder;
            if (m_tdfBuilder.m_impl->m_useOldNTDFFormat) {
                decoder = GCMDecryption::create(toBytes(m_decryptSymmetricKey), ivSpan);
            } else {
                constexpr auto ivSizeWithPadding = kIvPadding + kNanoTDFIvSize;
                std::array<gsl::byte, ivSizeWithPadding> iv{};

                std::memcpy(&iv[0] + kIvPadding, ivSpan.data(), kNanoTDFIvSize);
                decoder = GCMDecryption::create(toBytes(m_decryptSymmetricKey), toBytes(iv));
            }

            // Update the input buffer size after the IV is copied.
            inputSpan = inputSpan.subspan(kNanoTDFIvSize);

            // decrypt
            auto decryptedData = toWriteableBytes(m_decryptBuffer);
            decoder->decrypt(inputSpan, decryptedData);

            auto authTag = WriteableBytes{m_authTag};
            decoder->finish(authTag);
        }

        // Add the total size of encrypted payload(iv + cipher text + tag)
        bytesRead += cipherTextSize;

        // Adjust the buffer
        encryptedData = encryptedData.subspan(cipherTextSize);

        // Calculate the digest
        auto digest = calculateSHA256({startPoint, static_cast<gsl::span<const std::byte,-1>::index_type>(bytesRead)});

#if DEBUG_LOG
        auto digestAsBase64 = base64Encode(toBytes(digest));
        std::cout << "Digest on decrypt: " << digestAsBase64 << std::endl;
#endif

        // verify the signature
        if (payloadConfig.hasSignature()) {

            auto payloadConfig = m_header.getPayloadConfig();
            auto curveType = payloadConfig.getSignatureECCMode();
            auto curveName = ECCMode::GetEllipticCurveName(curveType);

            // Get the signer public key.
            auto compressKeyLength = ECCMode::GetECCompressedPubKeySize(curveType);
            std::vector<gsl::byte> signerPublicKey(compressKeyLength);
            std::memcpy(signerPublicKey.data(), encryptedData.data(), compressKeyLength);

            // Adjust the buffer
            encryptedData = encryptedData.subspan(compressKeyLength);

            // Generate a public key in pem format from ephemeral key.
            auto signerPublicKeyAsPem = ECKeyPair::GetPEMPublicKeyFromECPoint(toBytes(signerPublicKey), curveName);

#if DEBUG_LOG
            auto keyAsData = base64Encode(toBytes(signerPublicKeyAsPem));
            std::cout << "Decrypt ephemeral public key: " << keyAsData << std::endl;
#endif

            // Get the signature from tdf.
            auto signatureSize = ECCMode::GetECKeySize(curveType) * 2;
            m_signature.resize(signatureSize);
            std::memcpy(m_signature.data(), encryptedData.data(), signatureSize);

#if DEBUG_LOG
            auto sigData = base64Encode(toBytes(m_signature));
            std::cout << "Decrypt signature: " << sigData << std::endl;
#endif
            // Adjust the buffer
            encryptedData = encryptedData.subspan(signatureSize);

            // verify the signature.
            auto result = ECKeyPair::VerifyECDSASignature(toBytes(digest), toBytes(m_signature), signerPublicKeyAsPem);

            if (!result) {
                ThrowException("Failed to verify the payload signature.", VIRTRU_NANO_TDF_FORMAT_ERROR);
            }

            const auto& sdkSignerPublicKey = ECKeyPair::GetPEMPublicKeyFromX509Cert(m_tdfBuilder.m_impl->m_signerPublicKey);
#if DEBUG_LOG
            std::ostringstream os;
            os << "Signer public-key from TDF:" << "\n"
               <<  signerPublicKeyAsPem << "\n" << "\n"
               << "Signer public-key from SDK:" << "\n"
               << sdkSignerPublicKey << "\n";
            std::cout << os.str();
#endif

            if (!sdkSignerPublicKey.empty() && signerPublicKeyAsPem != sdkSignerPublicKey) {
                ThrowException("TDF is not signed with the correct entity.", VIRTRU_NANO_TDF_FORMAT_ERROR);
            }
        }

        return { reinterpret_cast<const char*>(m_decryptBuffer.data()), sizeOfPlainText};
    }

    /// Construct the header for encrypt.
    void NanoTDFImpl::createHeader(Header& header) {

        if (m_datasetMode && // In data set mode
            m_keyIterationCount > 0 && // Not the first iteration
            m_keyIterationCount != m_maxKeyIterations) { // Didn't reach the max iteration

            LogDebug("Reusing the header for dataset");

            // Use the old header.
            return;
        }

        if (m_datasetMode && (m_maxKeyIterations == m_keyIterationCount)) {

            auto curveName = ECCMode::GetEllipticCurveName(m_tdfBuilder.m_impl->m_ellipticCurveType);
            auto sdkECKeyPair = ECKeyPair::Generate(curveName);
            m_tdfBuilder.m_impl->m_privateKey = sdkECKeyPair->PrivateKeyInPEMFormat();
            m_tdfBuilder.m_impl->m_publicKey = sdkECKeyPair->PublicKeyInPEMFormat();

            m_tdfBuilder.m_impl->m_compressedPubKey =
                    ECKeyPair::CompressedECPublicKey(m_tdfBuilder.m_impl->m_publicKey);

            // Create a new policy.
            auto policyObject = PolicyObject::CopyDataFromPolicyObject(m_tdfBuilder.m_impl->m_policyObject);
            m_tdfBuilder.setPolicyObject(policyObject);

            LogDebug("Max iteration reached - create new header for dataset");
        }


        // Kas locator
        ResourceLocator kasLocator{m_tdfBuilder.m_impl->m_kasUrl};
        header.setKasLocator(std::move(kasLocator));

        // ECC mode
        ECCMode eccMode;
        eccMode.setEllipticCurve(m_tdfBuilder.m_impl->m_ellipticCurveType);
        eccMode.setECDSABinding(m_tdfBuilder.m_impl->m_useECDSABinding);
        header.setECCMode(std::move(eccMode));

        // Payload + Sig Mode
        SymmetricAndPayloadConfig payloadConfig;
        payloadConfig.setSymmetricCipherType(m_tdfBuilder.m_impl->m_cipher);
        payloadConfig.setHasSignature(m_tdfBuilder.m_impl->m_hasSignature);
        if (payloadConfig.hasSignature()) {
            payloadConfig.setSignatureECCMode(m_tdfBuilder.m_impl->m_signatureECCMode);
        }
        header.setPayloadConfig(std::move(payloadConfig));

        // Generate symmetric key.
        auto secret = ECKeyPair::ComputeECDHKey(m_tdfBuilder.m_impl->m_kasPublicKey,
                                                m_tdfBuilder.m_impl->m_privateKey);
        m_encryptSymmetricKey = ECKeyPair::calculateHKDF(toBytes(m_defaultSalt), toBytes(secret));

        // Payload info.
        PolicyInfo payloadInfo;
        std::array<gsl::byte, 32u> digest{};

        if (m_tdfBuilder.m_impl->m_policyType == NanoTDFPolicyType::EMBEDDED_POLICY_PLAIN_TEXT) {
            auto policy = m_tdfBuilder.m_impl->m_policyObject.toJsonString();

            payloadInfo.setEmbeddedPlainTextPolicy(toBytes(policy));
            digest = calculateSHA256(toBytes(m_policyPayload));
        } else if (m_tdfBuilder.m_impl->m_policyType == NanoTDFPolicyType::EMBEDDED_POLICY_ENCRYPTED) {

            auto policy = m_tdfBuilder.m_impl->m_policyObject.toJsonString();
            auto sizeOfTag = SymmetricAndPayloadConfig::SizeOfAuthTagForCipher(m_tdfBuilder.m_impl->m_cipher);

            // Update the size of policy payload buffer if needed.
            // NOTE: We always use IV value as zero so we don't add to cipher payload.
            std::size_t encryptedPayLoadSize = policy.size() + sizeOfTag;
            if (m_policyPayload.size() < encryptedPayLoadSize) {
                m_policyPayload.resize(encryptedPayLoadSize);
            }

            // Update auth tag size.
            m_authTag.resize(sizeOfTag);

            { // Encrypt the policy

                auto encryptedData = toWriteableBytes(m_policyPayload);

                // NOTE: Iv is not added to cipher payload.
                constexpr auto ivSizeWithPadding = kIvPadding + kNanoTDFIvSize;
                std::array<gsl::byte, ivSizeWithPadding> emptyIv{};

                auto encoder = GCMEncryption::create(toBytes(m_encryptSymmetricKey), emptyIv);
                encoder->encrypt(toBytes(policy), encryptedData);

                auto authTag = WriteableBytes{m_authTag};
                encoder->finish(authTag);

                // Copy tag at end
                std::copy(m_authTag.begin(), m_authTag.end(),
                          m_policyPayload.data() + policy.size());
            }

            payloadInfo.setEmbeddedEncryptedTextPolicy(toBytes(m_policyPayload));
            digest = calculateSHA256(toBytes(m_policyPayload));

        } else if (m_tdfBuilder.m_impl->m_policyType == NanoTDFPolicyType::REMOTE_POLICY) {

            // Sync the policy to server and add the url as policy body.
            ThrowException("Remote policy is not supported.", VIRTRU_NANO_TDF_FORMAT_ERROR);
        } else {
            ThrowException("Unknown nano tdf policy.", VIRTRU_NANO_TDF_FORMAT_ERROR);
        }

        if (m_tdfBuilder.m_impl->m_useECDSABinding) {
            // Calculate the ecdsa binding
            auto policyBinding = ECKeyPair::ComputeECDSASig(toBytes(digest), m_tdfBuilder.m_impl->m_privateKey);
            payloadInfo.setPolicyBinding(toBytes(policyBinding));
        } else {
            // Calculate the gmac binding
            auto gmac = toBytes(digest).last(kNanoTDFGMACLength);
            payloadInfo.setPolicyBinding(toBytes(gmac));
        }

        header.setPolicyInfo(std::move(payloadInfo));
        header.setEphemeralKey(m_tdfBuilder.m_impl->m_compressedPubKey);
    }

    /// Get the symmetric key from KAS(perform rewrap operation)
    std::vector<gsl::byte> NanoTDFImpl::getSymmetricKey(const Header& header) {

        bool requiresRewrap = needsRewrap(header);
        if (!requiresRewrap) {
            return m_decryptSymmetricKey;
        }

        Benchmark benchmark("Symmetric key from KAS");

        // Request body as part of JWT payload
        nlohmann::json requestBody;

        // Add the EC algorithm
        // NOTE: For now we only support 'secp256r1'
        requestBody[kAlgorithm] = kECDefaultAlgorithm;


        auto headerSize =  header.getTotalSize();
        std::vector<gsl::byte> headerData(headerSize);
        header.writeIntoBuffer(headerData);
        auto base64EncodedHeader = base64Encode(toBytes(headerData));

        nlohmann::json keyAccess;
        keyAccess[kNanoTDFHeader] = base64EncodedHeader;
        keyAccess[kKeyAccessType] = kKeyAccessRemote;
        keyAccess[kUrl] = m_tdfBuilder.m_impl->m_kasUrl;
        keyAccess[kProtocol] = kKasProtocol;
        requestBody[kKeyAccess] = keyAccess;

        // OIDC requires rewrap V2 and don't need entity object
        std::string rewrapUrl;
        if (m_tdfBuilder.m_impl->m_oidcMode) {
            requestBody[kClientPublicKey] = m_tdfBuilder.m_impl->m_publicKey;

            rewrapUrl = m_tdfBuilder.m_impl->m_kasUrl + kRewrapV2;
        } else {
            rewrapUrl = m_tdfBuilder.m_impl->m_kasUrl + kRewrap;

            // Add entity object
            auto entityJson = nlohmann::json::parse(m_tdfBuilder.m_impl->m_entityObject.toJsonString());
            requestBody[kEntity] = entityJson;
        }

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

        auto ecKeySize = ECCMode::GetECKeySize(m_tdfBuilder.m_impl->m_ellipticCurveType);
        if (ecKeySize == 32) {
            signedToken = builder.sign(jwt::algorithm::es256(m_tdfBuilder.m_impl->m_requestSignerPublicKey,
                                                          m_tdfBuilder.m_impl->m_requestSignerPrivateKey));
        } else if(ecKeySize == 48) {
            signedToken = builder.sign(jwt::algorithm::es384(m_tdfBuilder.m_impl->m_requestSignerPublicKey,
                                                          m_tdfBuilder.m_impl->m_requestSignerPrivateKey));
        } else if(ecKeySize == 66) {
            signedToken = builder.sign(jwt::algorithm::es512(m_tdfBuilder.m_impl->m_requestSignerPublicKey,
                                                          m_tdfBuilder.m_impl->m_requestSignerPrivateKey));
        } else {
            ThrowException("Fail to generate token for the given curve.", VIRTRU_CRYPTO_ERROR);
        }

        signedTokenRequestBody[kSignedRequestToken] = signedToken;
        auto signedTokenRequestBodyStr = to_string(signedTokenRequestBody);
        LogDebug(signedTokenRequestBodyStr);


        unsigned status = kHTTPBadRequest;
        std::string rewrapResponse;

        if (auto sp = m_tdfBuilder.m_impl->m_networkServiceProvider.lock()) { // Rely of callback interface

            std::promise<void> rewrapPromise;
            auto rewrapFuture = rewrapPromise.get_future();

            sp->executePost(rewrapUrl, m_tdfBuilder.m_impl->m_httpHeaders, to_string(signedTokenRequestBody),
                            [&rewrapPromise, &rewrapResponse, &status](unsigned int statusCode , std::string&& response) {

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

        } else {
            ThrowException("Network service not available", VIRTRU_NETWORK_ERROR);
        }

#if DEBUG_LOG
        std::cout << "The response from the KAS: " << rewrapResponse << '\n';
#endif

        auto payloadConfig = header.getPayloadConfig();
        auto authTagSize = SymmetricAndPayloadConfig::SizeOfAuthTagForCipher(payloadConfig.getCipherType());

        nlohmann::json jsonResponse;
        try{
            jsonResponse = nlohmann::json::parse(rewrapResponse);
        } catch (...){
            if (jsonResponse == ""){
                ThrowException("No rewrap response from KAS", VIRTRU_NETWORK_ERROR);
            }
            else{
                ThrowException("Could not parse KAS rewrap response: " + boost::current_exception_diagnostic_information() + "  with response: " + rewrapResponse, VIRTRU_NETWORK_ERROR);
            }
        }
        if (!jsonResponse.contains(kSessionPublicKey)) {
            const char* noPubkeyMsg = "No session public key in rewrap response";
            LogError(noPubkeyMsg);
            ThrowException(noPubkeyMsg, VIRTRU_NETWORK_ERROR);
        }
        const std::string sessionPublicKey = jsonResponse[kSessionPublicKey];

        if (!jsonResponse.contains(kEntityWrappedKey)) {
            const char* noKeyMsg = "No wrapped key in rewrap response";
            LogError(noKeyMsg);
            ThrowException(noKeyMsg, VIRTRU_NETWORK_ERROR);
        }
        const std::string wrappedKey = jsonResponse[kEntityWrappedKey];
        const auto& sdkPrivateKey = m_tdfBuilder.m_impl->m_privateKey;

        auto sessionKey = ECKeyPair::ComputeECDHKey(sessionPublicKey, sdkPrivateKey);
        sessionKey = ECKeyPair::calculateHKDF(toBytes(m_defaultSalt), toBytes(sessionKey));

        auto payloadKeK = base64Decode(wrappedKey);
        std::vector<gsl::byte> wrappedKeyOnRewrap;
        auto ivSize = (m_tdfBuilder.m_impl->m_useOldNTDFFormat) ? kNanoTDFIvSize : (kNanoTDFIvSize + kIvPadding);
        wrappedKeyOnRewrap.resize(payloadKeK.size() - ivSize - authTagSize);
        {
             auto data = toBytes(payloadKeK);

            // Copy the auth tag from the data buffer.
            m_authTag.resize(authTagSize);
            std::copy_n(data.last(authTagSize).data(), authTagSize, begin(m_authTag));

            // Update the input buffer size after the auth tag is copied.
            auto inputSpan = data.first(data.size() - authTagSize);
            auto decoder = GCMDecryption::create(toBytes(sessionKey), inputSpan.first(ivSize));

            // Update the input buffer size after the IV is copied.
            inputSpan = inputSpan.subspan(ivSize);

            // decrypt
            auto decryptedData = toWriteableBytes(wrappedKeyOnRewrap);
            decoder->decrypt(inputSpan, decryptedData);

            auto authTag = toWriteableBytes(m_authTag);
            decoder->finish(authTag);
        }

        return wrappedKeyOnRewrap;
    }

    /// Generate symmetric key(without communicating with KAS, using entity private-key).
    std::vector<gsl::byte> NanoTDFImpl::generateSymmetricKey(const Header& header) const {

        auto ephemeralPublicKey = ECKeyPair::GetPEMPublicKeyFromECPoint(header.getEphemeralKey(),
                                                                        header.getECCMode().getCurveName());

        auto secret = ECKeyPair::ComputeECDHKey(ephemeralPublicKey, m_tdfBuilder.m_impl->m_privateKey);
        auto symmetricKey = ECKeyPair::calculateHKDF(toBytes(m_defaultSalt), toBytes(secret));

        return symmetricKey;
    }

    /// Check if rewrap is needs to decrypt the dataset TDF.
    bool NanoTDFImpl::needsRewrap(const Header& header) {

        bool requiresRewrap = true;

        // Non dataset TDF requires a rewrap.
        if (!m_datasetMode) {
            return requiresRewrap;
        }

        auto ephemeralKey = header.getEphemeralKey();
        if (m_cachedEphemeralKey.empty()) {

            LogDebug("Cache the ephemeral key - rewrap requested");

            // cache the ephemeral key
            m_cachedEphemeralKey.resize(ephemeralKey.size());
            std::memcpy(&m_cachedEphemeralKey[0], ephemeralKey.data(), ephemeralKey.size());
        } else {

#if DEBUG_LOG
            std::cout << "ephemeralKey data: " << base64Encode(ephemeralKey) << std::endl;
            std::cout << "cachedEphemeralKey data: " << base64Encode(toBytes(m_cachedEphemeralKey)) << std::endl;
#endif

            auto keySize = m_cachedEphemeralKey.size();
            if (static_cast<std::size_t>(ephemeralKey.size()) != keySize) {
                ThrowException("Decrypt error with dataset TDF - wrong ephemeral key size", VIRTRU_CRYPTO_ERROR);
            }

            if (std::memcmp(ephemeralKey.data(),m_cachedEphemeralKey.data(), keySize) == 0) {
                requiresRewrap = false;
                LogDebug("Ephemeral key match - skill rewrap");
            } else {
                std::memcpy(&m_cachedEphemeralKey[0], ephemeralKey.data(), ephemeralKey.size());
                LogDebug("Ephemeral key mismatch - rewrap requested");
            }
        }

        return requiresRewrap;
    }

    /// Check if the size is within the limit of the nano TDF
    bool NanoTDFImpl::didExceedMaxSize(std::streampos size) {
        auto maxDataSizeAllowed = (m_datasetMode) ? kDatsetMaxMBBytes : kMaxTDFSize;
        return (static_cast<std::size_t>(size) > maxDataSizeAllowed);
    }

    /// Check if the file is in valid NanoTDF format.
    bool NanoTDFImpl::isValidNanoTDFFile(const std::string& filePath) {

        std::ifstream inStream( filePath, std::ios::binary | std::ios::ate);
        if (!inStream) {
            std::string errorMsg{"Failed to open file for reading - "};
            errorMsg.append(filePath);
            ThrowException(std::move(errorMsg), VIRTRU_SYSTEM_ERROR);
        }

        size_t fileSize = inStream.tellg();
        if (fileSize == 0) {
            return false;
        }

        inStream.seekg(0, std::ios::beg);
        std::vector<char> fileContent(fileSize);
        inStream.read(fileContent.data(), fileSize);

        std::string_view buffer{fileContent.data(), fileSize};
        return isValidNanoTDFData(toBytes(buffer));
    }

    /// Check if the data is in valid NanoTDF format.
    bool NanoTDFImpl::isValidNanoTDFData(Bytes nanoTDFData) {
        static const auto kSmallestTDFSize = 152;
        auto sizeOfTDF = nanoTDFData.size();
        auto bytesRead = 0;

        // Check the for smallest nanoTDF
        if (kSmallestTDFSize > nanoTDFData.size()) {
            return false;
        }

        try{
            // Parse the header
            Header header{nanoTDFData};
            auto headerSize = header.getTotalSize();

            if (headerSize >= sizeOfTDF) {
                return false;
            }

            // Adjust the buffer
            auto tdfData = nanoTDFData.subspan(header.getTotalSize());
            bytesRead += headerSize;

            // Get the payload config.
            auto payloadConfig = header.getPayloadConfig();
            auto sizeOfAuthTag = SymmetricAndPayloadConfig::SizeOfAuthTagForCipher(payloadConfig.getCipherType());

            boost::endian::big_uint24_t bgCipherTextSize{0};
            std::memcpy(&bgCipherTextSize, tdfData.data(), sizeof(boost::endian::big_uint24_t));
            std::uint32_t cipherTextSize = bgCipherTextSize;

            bytesRead += sizeof(boost::endian::big_uint24_t);

            if ((kNanoTDFIvSize + sizeOfAuthTag) > cipherTextSize) {
                return false;
            }

            // Adjust the buffer - cipher text length
            tdfData = nanoTDFData.subspan(sizeof(boost::endian::big_uint24_t));

            // Adjust the buffer - cipher text itself
            tdfData = nanoTDFData.subspan(cipherTextSize);
            bytesRead += cipherTextSize;

            if (payloadConfig.hasSignature()) {
                // 97 bytes of data ---> (signer public key + signature body)
                static const auto minSizeOfSignature = 97;
                if (sizeOfTDF >= (bytesRead + minSizeOfSignature)) {
                    return true;
                } else {
                    return false;
                }
            }
        } catch (...) {
            return false;
        }
        return true;
    }
}



