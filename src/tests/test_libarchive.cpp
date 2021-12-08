//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/08/26
//  Copyright 2019 Virtru Corporation
//

#define BOOST_TEST_MODULE test_tdf_archive_writer_suite

#include "tdf_constants.h"
#include "tdf_libarchive_writer.h"
#include "tdf_libarchive_reader.h"

#include <openssl/rand.h>
#include <boost/test/included/unit_test.hpp>
#include <chrono>

BOOST_AUTO_TEST_SUITE(test_tdf_archive_writer_suite)

    using namespace virtru;
    using namespace virtru::crypto;
    using namespace std::string_literals;

    const std::string tdfOutputFile{"sample.tdf"};
    const std::string outputFile{"sample.txt"};
    const std::string manifestFile{"0.manifest.json"};
    const std::string paylaodFile{"0.payload"};
    constexpr auto totalMbs = 2; // 20000; // 20GB
    constexpr auto oneMBSize = 1024 * 1024u;
    std::string kPreambleText{"VIRTRU"};
    std::string mainfestContents = R"({"displayName" : "effective-c++.pdf"})";

    BOOST_AUTO_TEST_CASE(test_tdf_archive_write) {
        using namespace virtru::crypto;

        // Open the tdf output file.
        std::ofstream outStream{ tdfOutputFile, std::ios_base::out | std::ios_base::binary };
        if (!outStream) {
            BOOST_FAIL("Failed to open file for writing.");
        }

        // Data sink callback for handling the output of the archive.
        auto datasinkCB =[&outStream](Bytes bytes) {
            if (!outStream.write(toChar(bytes.data()), bytes.size())) {
                return Status::Failure;
            } else {
                return Status::Success;
            }
        };

        auto totalSize = oneMBSize * totalMbs;
        std::vector<unsigned char> buffer(totalSize);
        RAND_bytes(buffer.data(), totalSize);

        auto t1 = std::chrono::high_resolution_clock::now();

        TDFArchiveWriter writer(datasinkCB, manifestFile, paylaodFile, (kPreambleText.size() + (totalMbs * oneMBSize)));
        auto inputBuffer = toBytes(buffer);

        // Add preamble
        writer.appendPayload(kPreambleText);

        // Write all the buffer.
        constexpr size_t kChunkSize = oneMBSize;
        size_t numberOfBytesWritten = inputBuffer.size();
        while (numberOfBytesWritten) {
            const auto inBufferSpan = inputBuffer.subspan(inputBuffer.size() - numberOfBytesWritten,
                                                          (std::min)(kChunkSize, numberOfBytesWritten));

            writer.appendPayload(inBufferSpan);
            numberOfBytesWritten -= inBufferSpan.size();
        }

        std::string manifest{ mainfestContents };
        writer.appendManifest(std::move(manifest));
        writer.finish();

        auto t2 = std::chrono::high_resolution_clock::now();
        auto timeSpent = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();

        std::cout << "Timespent on archive: " << timeSpent << "ms" << std::endl;
        BOOST_TEST_MESSAGE("Timespent on archive:" << timeSpent << "ms");
    }

    BOOST_AUTO_TEST_CASE(test_tdf_lib_archive_read) {

        auto t1 = std::chrono::high_resolution_clock::now();

        /// Open a file to read from archive.
        std::ifstream inStream {tdfOutputFile, std::ios_base::in | std::ios_base::binary };
        if (!inStream) {
            BOOST_FAIL("Failed to open file for reading.");
        }

        TDFArchiveReader reader{inStream, manifestFile, paylaodFile};

        /// Open a file to write the payload from archive.
        std::ofstream outStream{"sample1.txt", std::ios_base::out | std::ios_base::binary};
        if (!outStream) {
            BOOST_FAIL("Failed to open file for writing.");
        }

        std::vector<gsl::byte> preambleBuffer(kPreambleText.size());
        auto bytes = toWriteableBytes(preambleBuffer);
        reader.readPayloadExact(bytes);

        if (!outStream.write(toChar(bytes.data()), bytes.size())) {
            BOOST_FAIL("Failed to open file for writing.");
        }

        std::vector<gsl::byte> buffer(oneMBSize);
        bytes = toWriteableBytes(buffer);

        while (true) {
            reader.readPayload(bytes);

            if (!outStream.write(toChar(bytes.data()), bytes.size())) {
                BOOST_FAIL("Failed to open file for writing.");
            }

            if (bytes.size() < oneMBSize) {
                break; // done reading.
            }
        }

        auto t2 = std::chrono::high_resolution_clock::now();
        auto timeSpent = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();

        BOOST_TEST_MESSAGE("Timespent on unarchive:" << timeSpent << "ms");

        std::string text(reinterpret_cast<const char *>(&preambleBuffer[0]), preambleBuffer.size());

        BOOST_TEST(text == kPreambleText);
        BOOST_TEST(reader.getManifest() == mainfestContents);
        BOOST_CHECK(static_cast<std::size_t>(reader.getPayloadSize()) == (kPreambleText.size() + (totalMbs * oneMBSize)));
    }

BOOST_AUTO_TEST_SUITE_END()
