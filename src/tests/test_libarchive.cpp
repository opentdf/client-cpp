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

#include <openssl/rand.h>
#include <boost/test/included/unit_test.hpp>
#include <chrono>

void test_custom_zip_implementation(size_t fileMb) {

    using namespace virtru;

    std::string mainfestContents = R"({"displayName" : "effective-c++.pdf"})";
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
        std::string manifestStr(mainfestContents);
        writer.appendManifest(std::move(manifestStr));
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
        BOOST_TEST(manifest == mainfestContents);

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
    std::string mainfestContents = R"({"displayName" : "effective-c++.pdf"})";

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
        std::string manifest{ mainfestContents };
        writerv2.appendManifest(std::move(manifest));
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
