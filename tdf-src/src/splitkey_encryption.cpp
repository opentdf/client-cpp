//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/08.
//  Copyright 2019 Virtru Corporation
//

#include "tdf_exception.h"
#include "crypto/gcm_encryption.h"
#include "crypto/gcm_decryption.h"
#include "crypto/bytes.h"
#include "splitkey_encryption.h"
#include "sdk_constants.h"

namespace virtru {

    using namespace virtru::crypto;
    
    constexpr auto kKeyType = "split";

    /// Constructor
    SplitKey::SplitKey(CipherType chiperType) : m_cipherType{chiperType} {

        std::string cipherTypeStr = (chiperType == CipherType::Aes256GCM) ? "Aes256GCM" : "Aes265CBC";
        LogDebug("SplitKey object created of CipherType:" + cipherTypeStr);
    }

    /// Destructor
    SplitKey::~SplitKey() = default;


    /// Add KeyAccess object.
    void SplitKey::addKeyAccess(std::unique_ptr<KeyAccess> keyAccess) {

        if (!m_keyAccessObjects.empty()) {
            ThrowException("Only instance of 'Key Access Object' is supported");
        }

        m_keyAccessObjects.push_back(std::move(keyAccess));
    }

    /// Generate the manifest.
    tao::json::value SplitKey::getManifest() {

        if (m_keyAccessObjects.empty()) {
            ThrowException("'Key Access Object' is missing.");
        }

        /*
        Generate this manifest.
        {
            "integrityInformation": {
                "rootSignature": {
                    "alg": "HS256",
                    "sig": ""
                },
                "segmentHashAlg": "",
                "segmentSizeDefault": "",
                "segments": []
            },
            "keyAccess": [ {
                          "encryptedMetadata": "eyJjaXBoZXJ0ZXh0Ijo...VHNZQ3ZDMGp1YS9mQyJ9",
                          "policyBinding": "d24796e02f27912f86e97aebb92c3c33ea1f9bd33e004b5dee2d3513b932ac49",
                          "protocol": "kas",
                          "type": "wrapped",
                          "url": "api.virtru.com",
                          "wrappedKey": "TJPEgBcfPiOCERNDS+oj....g/F4h6EWoAgsSGfjkw=="
                          } ],
            "method": {
                "algorithm": "AES-256-GCM",
                "isStreamable": false,
                "iv": "4x7TsYCvC0jua/fC"
            },
            "policy": "eyJib2R5Ijp...zE5LTRhYmUtYWYzZC05ZThmYTY1N2RlZTIifQ==",
            "type": "split"
        } */

        // Construct Key Access Object.
        auto metadata = m_keyAccessObjects[0]->getMetaData();

        ByteArray<kGcmIvSize> iv = symmetricKey<kGcmIvSize>();
        auto base64IV = base64Encode(toBytes(iv));

        std::string encryptedMetadataStr{};
        if (!metadata.empty()) {

            std::vector<gsl::byte> encryptedData(kGcmIvSize + metadata.size() + kAesBlockSize);
            auto writeableBytes = WriteableBytes{encryptedData};
            encrypt(toBytes(iv), toBytes(metadata), writeableBytes);

            tao::json::value encryptedMetadataObj;
            encryptedMetadataObj[kCiphertext] = base64Encode(writeableBytes);
            encryptedMetadataObj[kIV] = base64IV;

            encryptedMetadataStr = to_string(encryptedMetadataObj);
        }

        auto keyAccessObject = m_keyAccessObjects[0]->construct(m_key, encryptedMetadataStr);

        // Create policy string for manifest.
        auto policyForManifest = m_keyAccessObjects[0]->policyForManifest();

        tao::json::value manifest;
        manifest[kKeyAccessType] = kKeyType;
        manifest[kKeyAccess] = tao::json::empty_array;
        manifest[kKeyAccess].emplace_back(tao::json::from_string(keyAccessObject.toJsonString()));

        tao::json::value method;
        method[kIsStreamable] = false;
        method[kIV] = base64IV;
        if (m_cipherType == CipherType::Aes256GCM) {
            method[kCipherAlgorithm] = kCipherAlgorithmGCM;
        } else {
            method[kCipherAlgorithm] = kCipherAlgorithmCBC;
        }

        manifest[kMethod] = method;

        tao::json::value rootSignature;
        rootSignature[kRootSignatureAlg] = kRootSignatureAlgDefault;
        rootSignature[kRootSignatureSig] = std::string{};

        tao::json::value integrityInformation;
        integrityInformation[kRootSignature] = rootSignature;
        integrityInformation[kSegmentSizeDefault] = std::string{};
        integrityInformation[kSegmentHashAlg] = std::string{};
        integrityInformation[kSegments] = tao::json::empty_array;

        manifest[kIntegrityInformation] = integrityInformation;
        manifest[kPolicy] = policyForManifest;

        return manifest;
    }

    /// Encrypt the data using the cipher.
    void SplitKey::encrypt(Bytes data, WriteableBytes& encryptedData) const {

        if (m_cipherType == CipherType::Aes265CBC) {
            ThrowException("AES-256-CBC is not supported.");
        }

        ByteArray<kGcmIvSize> iv = symmetricKey<kGcmIvSize>();

        encrypt (toBytes(iv), data, encryptedData);
    }
    
    /// Decrypt the data using the cipher.
    void SplitKey::decrypt(Bytes data, WriteableBytes& decryptedData) const {
        
        // Copy the auth tag from the data buffer.
        ByteArray<kAesBlockSize> tag;
        std::copy_n(data.last(kAesBlockSize).data(), kAesBlockSize, begin(tag));
        
        // Update the input buffer size after the auth tag is copied.
        auto inputSpan = data.first(data.size() - kAesBlockSize);
        auto symDecoder = GCMDecryption::create(toBytes(m_key), inputSpan.first(kGcmIvSize));
        
        // Update the input buffer size after the IV is copied.
        inputSpan = inputSpan.subspan(kGcmIvSize);
        
        // decrypt
        symDecoder->decrypt(inputSpan, decryptedData);
        auto authTag = WriteableBytes{tag};
        symDecoder->finish(authTag);
    }

    /// Set the wrapped key that will be used by split key encryption
    void SplitKey::setWrappedKey(const WrappedKey& key) {
        std::copy(key.begin(), key.end(), m_key.begin());
    }

    /// Encrypt the data using the cipher.
    void SplitKey::encrypt(Bytes iv, Bytes data, WriteableBytes& encryptedData) const {

        long finalSize =  iv.size() + data.size() +  kAesBlockSize;
        if (encryptedData.size() < finalSize) {
            ThrowException("Output buffer is too small.");
        }

        ByteArray<kAesBlockSize> tag;
        const auto bufferSpan = encryptedData;

        auto encryptedDataSize = 0;
        const auto final = finalizeSize(encryptedData, encryptedDataSize);

        // Adjust the span to add the IV vector at the start of the buffer
        auto encryptBufferSpan = bufferSpan.subspan(kGcmIvSize);

        auto encoder = GCMEncryption::create(toBytes(m_key), iv);
        encoder->encrypt(data, encryptBufferSpan);
        auto authTag = WriteableBytes{tag};
        encoder->finish(authTag);

        // Copy IV at start
        std::copy(iv.begin(), iv.end(), encryptedData.begin());

        // Copy tag at end
        std::copy(tag.begin(), tag.end(), encryptedData.begin() + kGcmIvSize + data.size());

        // Final size.
        encryptedDataSize = finalSize;
    }
} // namespace virtru
