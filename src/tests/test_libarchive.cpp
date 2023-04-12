//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/08/26
//  Copyright 2019 Virtru Corporation
//

#define BOOST_TEST_MODULE test_tdf_archive_writer_suite

#include "tdf_constants.h"
#include "file_io_provider.h"
#include "tdf_archive_writer.h"
#include "tdf_archive_reader.h"
#include "file_io_provider.h"
#include "manifest_data_model.h"

#include <openssl/rand.h>
#include <boost/test/included/unit_test.hpp>
#include <chrono>

void test_custom_zip_implementation(size_t fileMb) {

    using namespace virtru;

    const auto mainfestContents =
            R"({
  "payload": {
    "type": "reference",
    "url": "0.payload",
    "protocol": "zip",
    "isEncrypted": true
  },
  "encryptionInformation": {
    "type": "split",
    "keyAccess": [
      {
        "type": "wrapped",
        "url": "http://kas.example.com:4000",
        "protocol": "kas",
        "wrappedKey": "Y4wTa8tdKqSS3DUNMKTIUQq8Ti/WFrq26DRemybBgBcL/CyUZ98hFjDQgy4csBusEqwQ5zG+UAoRgkLkHiAw7hNAayAUCVRw6aUYRF4LWfcs2BM9k6d3bHqun0v5w==",
        "policyBinding": "ZGMwNGExZjg0ODFjNDEzZTk5NjdkZmI5MWFjN2Y1MzI0MTliNjM5MmRlMTlhYWM0NjNjN2VjYTVkOTJlODcwNA==",
        "encryptedMetadata": "OEOqJCS6mZsmLWJ38lh6EN2lDUA8OagL/OxQRQ=="
      }
    ],
    "method": {
      "algorithm": "AES-256-GCM",
      "isStreamable": true,
      "iv": "OEOqJCS6mZsmLWJ3"
    },
    "integrityInformation": {
      "rootSignature": {
        "alg": "HS256",
        "sig": "YjliMzAyNjg4NzA0NzUyYmUwNzY1YWE4MWNhNDRmMDZjZDU3OWMyYTMzNjNlNDYyNTM4MDA4YjQxYTdmZmFmOA=="
      },
      "segmentSizeDefault": 1000000,
      "segmentHashAlg": "GMAC",
      "segments": [
        {
          "hash": "ZmQyYjY2ZDgxY2IzNGNmZTI3ODFhYTk2ZjJhNWNjODA=",
          "segmentSize": 14056,
          "encryptedSegmentSize": 14084
        }
      ],
      "encryptedSegmentSizeDefault": 1000028
    },
    "policy": "eyJ1dWlkIjoiNjEzMzM0NjYtNGYwYS00YTEyLTk1ZmItYjZkOGJkMGI4YjI2IiwiYm9keSI6eyJhdHRyaWJ1dGVzIjpbXSwiZGlzc2VtIjpbInVzZXJAdmlydHJ1LmNvbSJdfX0="
  }
})";


    constexpr auto oneMBSize = 1024 * 1024u;
    constexpr auto tdfPayloadFileName = "0.payload";
    constexpr auto tdfManifestFileName = "0.manifest.json";
    const std::string tdfOutputFile{"test_writer_reader.tdf"};
    FileOutputProvider iop(tdfOutputFile);
    uint64_t totalSize = (uint64_t) oneMBSize * fileMb;

    std::string manifest{"test_custom_manifest.txt"};

    // Fill the 1 mb buffer with 'a'
    std::vector<char> inBuffer(oneMBSize);
    std::fill(inBuffer.begin(), inBuffer.end(), 'a');

    // STEP 1 - First create Payload file
    std::string payload{"test_payload_input.txt"};
    {
        std::ofstream outStream{payload.c_str(), std::ios_base::out | std::ios_base::binary};
        if (!outStream) {
            BOOST_FAIL("Failed to open file for writing sample data for partial decrypt.");
        }

        for (size_t index = 0; index < fileMb; index++) {
            outStream.write(inBuffer.data(), oneMBSize);
        }
    }

    auto t1 = std::chrono::high_resolution_clock::now();

    // STEP 2 - Create a .zip file similar to .tdf file with (payload and manifest)
    std::string archiveFile{"test_reader_writer_123.tdf"};
    {
        FileOutputProvider outputProvider{archiveFile};

        // Write '0.payload'
        TDFArchiveWriter writer{&outputProvider,
                                tdfManifestFileName,
                                tdfPayloadFileName};
        writer.setPayloadSize(oneMBSize*fileMb);
        for (size_t index = 0; index < fileMb; index++) {
            auto bytes = toWriteableBytes(inBuffer);
            writer.appendPayload(bytes);
        }

        // Write '0.manifest.json'
        auto dataModel = ManifestDataModel::CreateModelFromJson(mainfestContents);
        writer.appendManifest(dataModel);
        writer.finish();
    }

    // STEP 3 -unzip the file and get payload and manifest
    std::string payloadOut{"test_payload_output.txt"};
    {
        FileInputProvider inputProvider{archiveFile};
        TDFArchiveReader reader{&inputProvider,
                                tdfManifestFileName,
                                tdfPayloadFileName};

        auto manifest = reader.getManifest();



        auto dataModel1 = ManifestDataModel::CreateModelFromJson(manifest);
        auto dataModel2 = ManifestDataModel::CreateModelFromJson(mainfestContents);
        BOOST_TEST(dataModel1.encryptionInformation.policy == dataModel2.encryptionInformation.policy);

        //FileOutputProvider outputProvider{payloadOut};
        std::ofstream outStream{payloadOut.c_str(), std::ios_base::out | std::ios_base::binary};
        if (!outStream) {
            BOOST_FAIL("Failed to open file for writing sample data.");
        }

        size_t filePosition{};
        for (auto index = 0; index < fileMb; index++) {
            auto bytes = toWriteableBytes(inBuffer);
            reader.readPayload(filePosition, oneMBSize, bytes);

            // Write to a file
            outStream.write(reinterpret_cast<char *>(bytes.data()), oneMBSize);

            filePosition += oneMBSize;
        }
    }

    auto t2 = std::chrono::high_resolution_clock::now();
    auto timeSpent = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();

    std::cout << "Time spent on zip and unzip: " << timeSpent << "ms" << std::endl;
    BOOST_TEST_MESSAGE("Time spent on zip and unzip:" << timeSpent << "ms");

    {
        std::ifstream ifs1(payload);
        std::ifstream ifs2(payloadOut);

        std::istream_iterator<char> b1(ifs1), e1;
        std::istream_iterator<char> b2(ifs2), e2;

        BOOST_CHECK_EQUAL_COLLECTIONS(b1, e1, b2, e2);
    }

    remove(payload.c_str());
    remove(payloadOut.c_str());
    remove(archiveFile.c_str());
}

BOOST_AUTO_TEST_SUITE(test_tdf_archive_writer_suite)

    using namespace virtru;
    using namespace virtru::crypto;
    using namespace std::string_literals;

    const std::string tdfOutputFile{"sample.tdf"};
    const std::string outputFile{"sample.txt"};
    const std::string manifestFile{"0.manifest.json"};
    const std::string payloadFile{"0.payload"};
    constexpr auto totalMbs = 2; // 20000; // 20GB
    constexpr auto oneMBSize = 1024 * 1024u;
    std::string kPreambleText{"VIRTRU"};
    const auto mainfestContents =
            R"({
  "payload": {
    "type": "reference",
    "url": "0.payload",
    "protocol": "zip",
    "isEncrypted": true
  },
  "encryptionInformation": {
    "type": "split",
    "keyAccess": [
      {
        "type": "wrapped",
        "url": "http://kas.example.com:4000",
        "protocol": "kas",
        "wrappedKey": "Y4wTa8tdKqSS3DUNMKTIUQq8Ti/WFrq26DRemybBgBcL/CyUZ98hFjDQgy4csBusEqwQ5zG+UAoRgkLkHiAw7hNAayAUCVRw6aUYRF4LWfcs2BM9k6d3bHqun0v5w==",
        "policyBinding": "ZGMwNGExZjg0ODFjNDEzZTk5NjdkZmI5MWFjN2Y1MzI0MTliNjM5MmRlMTlhYWM0NjNjN2VjYTVkOTJlODcwNA==",
        "encryptedMetadata": "OEOqJCS6mZsmLWJ38lh6EN2lDUA8OagL/OxQRQ=="
      }
    ],
    "method": {
      "algorithm": "AES-256-GCM",
      "isStreamable": true,
      "iv": "OEOqJCS6mZsmLWJ3"
    },
    "integrityInformation": {
      "rootSignature": {
        "alg": "HS256",
        "sig": "YjliMzAyNjg4NzA0NzUyYmUwNzY1YWE4MWNhNDRmMDZjZDU3OWMyYTMzNjNlNDYyNTM4MDA4YjQxYTdmZmFmOA=="
      },
      "segmentSizeDefault": 1000000,
      "segmentHashAlg": "GMAC",
      "segments": [
        {
          "hash": "ZmQyYjY2ZDgxY2IzNGNmZTI3ODFhYTk2ZjJhNWNjODA=",
          "segmentSize": 14056,
          "encryptedSegmentSize": 14084
        }
      ],
      "encryptedSegmentSizeDefault": 1000028
    },
    "policy": "eyJ1dWlkIjoiNjEzMzM0NjYtNGYwYS00YTEyLTk1ZmItYjZkOGJkMGI4YjI2IiwiYm9keSI6eyJhdHRyaWJ1dGVzIjpbXSwiZGlzc2VtIjpbInVzZXJAdmlydHJ1LmNvbSJdfX0="
  }
})";


    BOOST_AUTO_TEST_CASE(test_tdf_lib_archive_new_writer) {
        const std::string tdfOutputFile{"sample_zip.tdf"};
        FileOutputProvider iop(tdfOutputFile);
        auto totalMB = 50;
        uint64_t totalSize = (uint64_t)oneMBSize * totalMB;
        std::vector<unsigned char> buffer(totalSize);
        RAND_bytes(buffer.data(), totalSize);
        TDFArchiveWriter writerv2(&iop, manifestFile, payloadFile);
        writerv2.setPayloadSize(kPreambleText.size() + totalSize);
        auto inputBuffer = toBytes(buffer);

        // Add preamble
        writerv2.appendPayload(kPreambleText);

        // Write all the buffer.
        constexpr size_t kChunkSize = oneMBSize;
        size_t numberOfBytesWritten = inputBuffer.size();
        while (numberOfBytesWritten) {
            const auto inBufferSpan = inputBuffer.subspan(inputBuffer.size() - numberOfBytesWritten,
                                                          (std::min)(kChunkSize, numberOfBytesWritten));

            writerv2.appendPayload(inBufferSpan);
            numberOfBytesWritten -= inBufferSpan.size();
        }
        ManifestDataModel dataModel;
        writerv2.appendManifest(dataModel);
        writerv2.finish();
    }

    BOOST_AUTO_TEST_CASE(test_tdf_lib_archive_new_writer_reader) {

        // Array of file size in mb
        std::array<size_t, 4> vec{1, 5, 10, 50};

        for (const auto& fileMB : vec) {
            test_custom_zip_implementation(fileMB);
        }
    }

BOOST_AUTO_TEST_SUITE_END()
