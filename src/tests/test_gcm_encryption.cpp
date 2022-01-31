//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/16
//  Copyright 2019 Virtru Corporation
//

#define BOOST_TEST_MODULE test_gcm_encoding_suite

#include "gcm_encryption.h"
#include "bytes.h"
#include "tdf_exception.h"
#include "crypto_utils.h"

#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(test_gcm_encoding_suite)

    constexpr size_t kChunkSize = 25u;
    constexpr size_t kBufferSize = 1024u;

    using namespace std::string_literals;
    using namespace virtru::crypto;

    const static auto kPlainText =
            "Ehrsam, Meyer, Smith and Tuchman invented the Cipher Block Chaining (CBC) mode of operation in 1976. "
            "In CBC mode, each block of plaintext is XORed with the previous ciphertext block before being encrypted. "
            "This way, each ciphertext block depends on all plaintext blocks processed up to that point. "
            "To make each message unique, an initialization vector must be used in the first block."s;

    const static auto kEncryptedAes256GCMBase64 =
            "RFo0e8Q+dFtuBtMh0VGZk5u7BlXwUZvSbtPEZNJlrm5b893voEVhuqnQNF7HoPAN/Un0OL72cUJiLc8h0ufHhA6L3VtXFqSXTr+ebsphfTW2HI"
            "kV7s3p4MD2eg/XwjsAt4FxkYV/FoeQti8TSlkCfytnq6ClqQnYYw00UKNHoAb7uromnTz/IBeRRvBxQgg26arS5AvIHD9UdN4LfAvTXcsn+OfK"
            "9mWhiM9A6WAJSr/D/LXgvn6YLmtzd5txDpYrpR/2H6AI1yJDuv5CXjrsxbK1kk2gORWSCqozACQXnMT1v3nnSwr+DT6rXZ/ZdS5jl3hOdqQnCU"
            "477M2pJ1mWh87pmb6w9TyGqvwpuvc2Y36Z03LbrXPJw/sQWhRDIUtWTnPJsHKch/H+Dbw6Tdj7HnJb4o/7+IT9GpvgnDgNJ55yfZsAU655+Cag"
            "X5tCvCA+hYixxsD+/J5e+frs+SBacKQzNeq01IxA0vsVkoSryG+4sFu3nZI/gtgtu1vL693B"s;

    const static std::array<std :: uint8_t, 32u> kSymmetricKey = {
            0xf0, 0x5b, 0x5f, 0xab, 0x91, 0x60, 0xf3, 0xc6,
            0x51, 0x6a, 0x83, 0x3e, 0x82, 0xa3, 0x56, 0x62,
            0x65, 0xb1, 0x68, 0x01, 0xf2, 0x9f, 0x9a, 0x55,
            0xe2, 0x01, 0xba, 0xc6, 0x8a, 0xb8, 0x91, 0xf6
    };

    const static std::array<std :: uint8_t, 12u> kIV = {
            0x1a, 0x5f, 0x26, 0xf9, 0x5f, 0x81,
            0xf4, 0x42, 0x94, 0x60, 0x3b, 0x73
    };

    /// For testing message data authenticity (integrity).
    const static std::array<std :: uint8_t, 16> kAuthTagNoAad = {0x6c, 0x61, 0xc4, 0x6b, 0x8f, 0x80, 0x8e, 0x27, 0x67, 0x76, 0xaa, 0x24, 0xbb, 0x1d, 0x10, 0x77};
    const static std::vector<std :: uint8_t> kAuthAad = {0xeb, 0xfe, 0xa8, 0x74, 0x64, 0x28, 0x80, 0x96, 0x7b, 0x8a, 0x2a, 0x5f};
    const static std::array<std :: uint8_t, 16> kAuthTagForDefinedAad = {0xf3, 0xc1, 0x92, 0x81, 0x89, 0xe8, 0x9, 0x4, 0x61, 0x5f, 0xc1, 0x38, 0x5, 0x44, 0x7a, 0xb8};


    BOOST_AUTO_TEST_CASE(test_gcm_encoding_with_no_aad) {

        ByteArray<16> tag;
        auto encoder = GCMEncryption::create(toBytes(kSymmetricKey), toBytes(kIV));

        ByteArray<kBufferSize> buffer1;
        const auto bufferSpan = WriteableBytes{buffer1};

        auto outBufferSpan = bufferSpan;
        encoder->encrypt(toBytes(kPlainText), outBufferSpan);

        auto authTag = WriteableBytes{tag};
        encoder->finish(authTag);

        auto base64EncryptedData = base64Encode(bufferSpan.first(outBufferSpan.size()));
        BOOST_TEST(kEncryptedAes256GCMBase64 == base64EncryptedData);
        BOOST_TEST(toBytes(kAuthTagNoAad) == toBytes(tag));

        /// Test with wrapped key by copying the orginal key.
        WrappedKey key;
        for (size_t i = 0 ; i < kSymmetricKey.size(); i++) {
            key[i] = static_cast<gsl::byte>(kSymmetricKey[i]);
        }

        std::vector<gsl::byte> buffer(kBufferSize);
        auto writeableBytes = toWriteableBytes(buffer);

        encoder = GCMEncryption::create(toBytes(key), toBytes(kIV));
        encoder->encrypt(toBytes(kPlainText), writeableBytes);

        authTag = WriteableBytes{tag};
        encoder->finish (authTag);

        std::string decryptedMessage(reinterpret_cast<const char *>(&writeableBytes[0]), writeableBytes.size());
        base64EncryptedData = base64Encode(decryptedMessage);
        BOOST_TEST(kEncryptedAes256GCMBase64 == base64EncryptedData);
        BOOST_TEST(toBytes(kAuthTagNoAad) == toBytes(tag));
    }

    BOOST_AUTO_TEST_CASE(test_gcm_encoding_with_same_io_buffer) {

        ByteArray<16> tag;
        
        std::vector<gsl::byte> buffer(kPlainText.size());
        std::transform(kPlainText.begin(), kPlainText.end(), buffer.begin(),
                       [] (char c) { return gsl::byte(c); });

        auto writeableBytes = toWriteableBytes(buffer);
        auto encoder = GCMEncryption::create(toBytes(kSymmetricKey), toBytes(kIV));
        
        /// Passing the same buffer as input and output
        encoder->encrypt(writeableBytes, writeableBytes);

        auto authTag = WriteableBytes{tag};
        encoder->finish (authTag);

        auto base64EncryptedData = base64Encode(writeableBytes);
        BOOST_TEST(kEncryptedAes256GCMBase64 == base64EncryptedData);
        BOOST_TEST(toBytes(kAuthTagNoAad) == toBytes(tag));
    }

    BOOST_AUTO_TEST_CASE (test_gcm_encoding_with_stream_and_no_aad) {
        ByteArray<16> authTag;
        
        auto encoder = GCMEncryption::create(toBytes(kSymmetricKey), toBytes(kIV));
        auto inputBuffer = toBytes(kPlainText);
        
        ByteArray<kBufferSize> buffer;
        const auto bufferSpan = WriteableBytes{buffer};
        
        auto numberOfEncryptedBytes = 0u;
        size_t numberOfBytesToEncrypt = inputBuffer.size();
        while (numberOfBytesToEncrypt) {
            
            auto inputBufferSpan = inputBuffer.subspan(inputBuffer.size() - numberOfBytesToEncrypt,
                                                       (std::min)(kChunkSize, numberOfBytesToEncrypt));
            auto outputBufferSpan = bufferSpan.subspan(numberOfEncryptedBytes);
            
            encoder->encrypt(inputBufferSpan, outputBufferSpan);
            
            numberOfBytesToEncrypt -= inputBufferSpan.size();
            numberOfEncryptedBytes += outputBufferSpan.size();
        }

        auto tag = WriteableBytes{authTag};
        encoder->finish(tag);
        
        const std::string base64Representation = base64Encode(bufferSpan.first(numberOfEncryptedBytes));
        BOOST_TEST(kEncryptedAes256GCMBase64 == base64Representation);
        BOOST_TEST(toBytes(kAuthTagNoAad) == toBytes(authTag));
    }

    BOOST_AUTO_TEST_CASE(test_gcm_encoding_with_small_out_buffer) {
        
        auto encoder = GCMEncryption::create(toBytes(kSymmetricKey), toBytes(kIV));
        
        std::vector<gsl::byte> outBuffer(kPlainText.size() - 1);
        auto outputBufferSpan = WriteableBytes {outBuffer};
        
        BOOST_CHECK_THROW(encoder->encrypt(toBytes(kPlainText), outputBufferSpan), virtru::Exception);
    }

    BOOST_AUTO_TEST_CASE(test_gcm_encoding_with_defined_aad) {
        
        ByteArray<16> authTag;
        auto encoder = GCMEncryption::create(toBytes(kSymmetricKey),
                                          toBytes(kIV),
                                          toBytes(kAuthAad));
        
        ByteArray<kBufferSize> buffer;
        auto outputBufferSpan = WriteableBytes{buffer};
        
        encoder->encrypt(toBytes(kPlainText), outputBufferSpan);

        auto tag = WriteableBytes{authTag};
        encoder->finish(tag);
        
        const std::string base64Representation = base64Encode(outputBufferSpan);
        BOOST_TEST(kEncryptedAes256GCMBase64 == base64Representation);
        BOOST_TEST(toBytes(kAuthTagForDefinedAad) == toBytes(authTag));
    }

BOOST_AUTO_TEST_SUITE_END()
