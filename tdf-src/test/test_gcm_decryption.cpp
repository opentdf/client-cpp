//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/04/16
//  Copyright 2019 Virtru Corporation
//

#define BOOST_TEST_MODULE test_gcm_decoding_suite

#include "gcm_decryption.h"
#include "bytes.h"
#include "tdf_exception.h"
#include "crypto_utils.h"

#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(test_gcm_decoding_suite)

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
    static std::array<std :: uint8_t, 16u> kAuthTagNoAad = {0x6c, 0x61, 0xc4, 0x6b, 0x8f, 0x80, 0x8e, 0x27, 0x67, 0x76, 0xaa, 0x24, 0xbb, 0x1d, 0x10, 0x77};
    const static std::vector<std :: uint8_t> kAuthAad = {0xeb, 0xfe, 0xa8, 0x74, 0x64, 0x28, 0x80, 0x96, 0x7b, 0x8a, 0x2a, 0x5f};
    static std::array<std :: uint8_t, 16> kAuthTagForDefinedAad = {0xf3, 0xc1, 0x92, 0x81, 0x89, 0xe8, 0x9, 0x4, 0x61, 0x5f, 0xc1, 0x38, 0x5, 0x44, 0x7a, 0xb8};


    BOOST_AUTO_TEST_CASE(test_gcm_decoding_with_no_aad) {

        auto decoder = GCMDecryption::create(toBytes(kSymmetricKey), toBytes(kIV));
        auto cipherText = base64Decode(toBytes(kEncryptedAes256GCMBase64));

        ByteArray<kBufferSize > buffer;
        auto bufferSpan = WriteableBytes{buffer};

        // This extra span is not required because decrypt updates
        // the size but to exercise some span features.
        auto outBufferSpan = bufferSpan;
        decoder->decrypt(toBytes(cipherText), outBufferSpan);

        auto authTag = WriteableBytes{ toWriteableBytes(kAuthTagNoAad) };
        decoder->finish(authTag);

        BOOST_TEST(toBytes(kPlainText) == toBytes(bufferSpan.first(outBufferSpan.size())));
    }

    BOOST_AUTO_TEST_CASE(test_gcm_decoding_with_same_io_buffer) {

        auto cipherText = base64Decode(toBytes(kEncryptedAes256GCMBase64));
        std::vector<gsl::byte> buffer(cipherText.size());
        std::transform(cipherText.begin(), cipherText.end(), buffer.begin(),
                       [] (char c) { return gsl::byte(c); });

        auto writeableBytes = toWriteableBytes(buffer);
        auto decoder = GCMDecryption::create(toBytes(kSymmetricKey), toBytes(kIV));

        /// Passing the same buffer as input and output
        decoder->decrypt(writeableBytes, writeableBytes);

        auto authTag = WriteableBytes{ toWriteableBytes(kAuthTagNoAad) };
        decoder->finish(authTag);
        
        std::string decryptedMessage(reinterpret_cast<const char *>(&writeableBytes[0]), writeableBytes.length());
        BOOST_TEST(kPlainText == decryptedMessage);
    }

    BOOST_AUTO_TEST_CASE(test_gcm_encoding_with_stream_and_no_aad) {
        
        auto cipherText = base64Decode(toBytes(kEncryptedAes256GCMBase64));
        auto decoder = GCMDecryption::create(toBytes(kSymmetricKey), toBytes(kIV));
        
        ByteArray<kBufferSize> buffer;
        const auto bufferSpan = WriteableBytes{buffer};
        
        size_t numberOfEncryptedBytes = 0u;
        size_t numberOfBytesToEncrypt = cipherText.size();
        
        while (numberOfBytesToEncrypt) {
            
            const auto inBufferSpan = toBytes(cipherText).subspan(cipherText.size() - numberOfBytesToEncrypt,
                                                                  (std::min)(kChunkSize, numberOfBytesToEncrypt));
            
            auto outBufferSpan = bufferSpan.subspan(numberOfEncryptedBytes);
            decoder->decrypt(inBufferSpan, outBufferSpan);
            
            numberOfBytesToEncrypt -= inBufferSpan.size();
            numberOfEncryptedBytes += outBufferSpan.size();
        }

        auto authTag = WriteableBytes{ toWriteableBytes(kAuthTagNoAad) };
        decoder->finish(authTag);
        BOOST_TEST(toBytes(kPlainText) == toBytes(bufferSpan.first(numberOfEncryptedBytes)));
    }

    BOOST_AUTO_TEST_CASE(test_gcm_decoding_with_small_out_buffer ) {
        
        auto decoder = GCMDecryption::create(toBytes(kSymmetricKey), toBytes(kIV));
        auto cipherText = base64Decode(toBytes(kEncryptedAes256GCMBase64));

        std::vector<gsl :: byte> outBuffer(cipherText.size() - 1);
        auto outBufferSpan = WriteableBytes{outBuffer};
    
        BOOST_CHECK_THROW(decoder->decrypt(toBytes(cipherText), outBufferSpan), virtru::Exception);
    }

    BOOST_AUTO_TEST_CASE(test_gcm_decoding_with_defined_aad) {
        
        auto decoder = GCMDecryption::create(toBytes(kSymmetricKey), toBytes(kIV), toBytes(kAuthAad));
        auto cipherText = base64Decode(toBytes(kEncryptedAes256GCMBase64));
        
        gsl::byte buffer[kBufferSize];
        auto bufferSpan = WriteableBytes { buffer };
        
        decoder->decrypt(toBytes(cipherText), bufferSpan);

        auto authTag = WriteableBytes{ toWriteableBytes(kAuthTagForDefinedAad)};
        decoder->finish(authTag);
        
        BOOST_TEST(toBytes(kPlainText) == toBytes(bufferSpan));
    }

BOOST_AUTO_TEST_SUITE_END()

