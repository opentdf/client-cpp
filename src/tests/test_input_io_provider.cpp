/*
* Copyright 2022 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
* Created by Patrick Mancuso on 5/3/22.
*/

#define BOOST_TEST_MODULE test_input_io_provider

#include <iostream>
#include <iomanip>

#include "tdf_exception.h"
#include "logger.h"
#include "stdlib.h"
#include "stdio.h"

#include "boost/test/included/unit_test.hpp"
#include "crypto/crypto_utils.h"
#include "sdk_constants.h"
#include "network/http_client_service.h"
#include "network_interface.h"

#include "file_io_provider.h"
#include "s3_io_provider.h"

BOOST_AUTO_TEST_SUITE(test_input_io_provider_suite)


    using namespace virtru;
    const unsigned long buffer_size = 1024;// 1024 * 1024 * 1; // 1 megabyte

    class MockNetwork : public INetwork {
    public: //INetwork members
        virtual void executeGet(const std::string &/*url*/, const HttpHeaders &headers, HTTPServiceCallback &&callback, const std::string& /*ca*/, const std::string& /*key*/, const std::string& /*cert*/) override
        {
            LogTrace("Mock Service::Get");

            size_t rangeBegin = 0;
            size_t rangeEnd = buffer_size-1;
            bool bFoundRange = false;

            // Set rangeBegin and rangeEnd from headers if supplied
            auto hPos = headers.find(kRangeRequest);
            if (hPos != headers.end()) {
                bFoundRange = true;
                std::string rangeSpec = hPos->second;
                std::string sBegin = rangeSpec.substr(6, rangeSpec.find("-")-6);
                rangeBegin = atol(sBegin.c_str());
                std::string sEnd = rangeSpec.substr(rangeSpec.find("-")+1);
                rangeEnd = atol(sEnd.c_str());
            }

            std::vector<std::byte> buffer((rangeEnd - rangeBegin)+1);
            WriteableBytes bytes = WriteableBytes{buffer};

            std::byte value;
            for (unsigned long i = rangeBegin; i <= rangeEnd; i++) {
                value = static_cast<std::byte>(i & 0xFF);
                buffer[i-rangeBegin] = value;
            }

            //std::string data(static_cast<const char*>(static_cast<void*>(buffer.data())), buffer.size());
            int response = bFoundRange ? 206 : 200;
            std::string data(toChar(bytes.data()), bytes.size());
            callback(response, std::move(data));
        }

        virtual void executePut(const std::string &/*url*/, const HttpHeaders &/*headers*/, std::string &&/*body*/, HTTPServiceCallback &&callback, const std::string& /*ca*/, const std::string& /*key*/, const std::string& /*cert*/) override
        {
            LogTrace("Mock Service::Put");
            callback(400, "");
        }

        virtual void executeHead(const std::string &/*url*/, const HttpHeaders &/*headers*/, HTTPServiceCallback &&callback, const std::string& /*ca*/, const std::string& /*key*/, const std::string& /*cert*/) override {
            LogTrace("Mock Service::Head");
            std::ostringstream fakeContentLength;
            fakeContentLength << "Content-Length: " << buffer_size << "\nHost: someHost";
            callback(200, fakeContentLength.str());  // This should be returned in the headers, but put it here to simulate what the real one does
        }

        virtual void executePost(const std::string &/*url*/, const HttpHeaders &/*headers*/, std::string &&/*body*/, HTTPServiceCallback &&callback, const std::string& /*ca*/, const std::string& /*key*/, const std::string& /*cert*/) override
        {
            LogTrace("Mock Service::Post");
            callback(400, "");
        }

        virtual void executePatch(const std::string &/*url*/, const HttpHeaders &/*headers*/, std::string &&/*body*/, HTTPServiceCallback &&callback, const std::string& /*ca*/, const std::string& /*key*/, const std::string& /*cert*/) override
        {
            std::cout << "Mock Service::executePatch";
            callback(400, "");
        }

    };


 static bool verifyReadDataCorrect(size_t index, size_t length, WriteableBytes &buffer) {

     std::byte expected;
     std::byte actual;
     unsigned long i;
     for (i = 0; i < length; i++) {
         expected = static_cast<std::byte>((index+i) & 0xFF);
         actual = buffer[i];

         if (actual != expected) {
             std::ostringstream oss;
             char xExpected[5];
             char xActual[5];
             sprintf(xExpected, "%0.2x", static_cast<unsigned int>(expected));
             sprintf(xActual, "%0.2x", static_cast<unsigned int>(actual));
             oss << "i=" << i << " expected=" << xExpected << " actual=" << xActual;
             LogError("Bad data in read buffer: " + oss.str());
             return false;
         }
     }
     return true;
 }

void test_input_provider_read(IInputProvider& inputProvider) {
     try {
         std::vector<std::byte> buffer(buffer_size);
         WriteableBytes bytes = WriteableBytes{buffer};

         size_t index = 0;
         size_t length = buffer_size;

         inputProvider.readBytes(index, length, bytes);

         if (!verifyReadDataCorrect(index, length, bytes)) {
             std::ostringstream oss;
             oss << "Bad data in read buffer at line " << __LINE__;
             BOOST_FAIL(oss.str());
         }

     } catch (std::exception e) {
         LogDebug(e.what());
         std::ostringstream oss;
         oss << e.what();
         BOOST_FAIL("Caught exception: " + oss.str());
     }
     LogDebug("Finished reading");
}

void test_input_provider_read_partial_mid(IInputProvider& inputProvider) {
        try {
            std::vector<std::byte> buffer(buffer_size);
            WriteableBytes bytes = WriteableBytes{buffer};

            size_t index = 10;
            size_t length = 30;

            inputProvider.readBytes(index, length, bytes);

            if (!verifyReadDataCorrect(index, length, bytes)) {
                std::ostringstream oss;
                oss << "Bad data in read buffer at line " << __LINE__;
                BOOST_FAIL(oss.str());
            }
        } catch (std::exception e) {
            LogDebug(e.what());
            std::ostringstream oss;
            oss << e.what();
            BOOST_FAIL("Caught exception: " + oss.str());
        }
        LogDebug("Finished reading");
    }

  void test_input_provider_read_partial_begin(IInputProvider& inputProvider) {
        try {
            std::vector<std::byte> buffer(buffer_size);
            WriteableBytes bytes = WriteableBytes{buffer};

            size_t index = 0;
            size_t length = 10;

            inputProvider.readBytes(index, length, bytes);

            if (!verifyReadDataCorrect(index, length, bytes)) {
                std::ostringstream oss;
                oss << "Bad data in read buffer at line " << __LINE__;
                BOOST_FAIL(oss.str());
            }
        } catch (std::exception e) {
            LogDebug(e.what());
            std::ostringstream oss;
            oss << e.what();
            BOOST_FAIL("Caught exception: " + oss.str());
        }
        LogDebug("Finished reading");
    }

void test_input_provider_read_partial_end(IInputProvider& inputProvider) {
        try {
            std::vector<std::byte> buffer(buffer_size);
            WriteableBytes bytes = WriteableBytes{buffer};

            size_t index = buffer_size-10;
            size_t length = 10;

            inputProvider.readBytes(index, length, bytes);

            if (!verifyReadDataCorrect(index, length, bytes)) {
                std::ostringstream oss;
                oss << "Bad data in read buffer at line " << __LINE__;
                BOOST_FAIL(oss.str());
            }
        } catch (std::exception e) {
            LogDebug(e.what());
            std::ostringstream oss;
            oss << e.what();
            BOOST_FAIL("Caught exception: " + oss.str());
        }
        LogDebug("Finished reading");
    }

void test_input_provider_read_partial_multiple(IInputProvider& inputProvider) {
        try {
            std::vector<std::byte> buffer(buffer_size);
            WriteableBytes bytes = WriteableBytes{buffer};

            size_t index = buffer_size-10;
            size_t length = 10;

            inputProvider.readBytes(index, length, bytes);

            if (!verifyReadDataCorrect(index, length, bytes)) {
                std::ostringstream oss;
                oss << "Bad data in read buffer at line " << __LINE__;
                BOOST_FAIL(oss.str());
            }

            index = 0;
            inputProvider.readBytes(index, length, bytes);

            if (!verifyReadDataCorrect(index, length, bytes)) {
                std::ostringstream oss;
                oss << "Bad data in read buffer at line " << __LINE__;
                BOOST_FAIL(oss.str());
            }

            index = 20;
            inputProvider.readBytes(index, length, bytes);

            if (!verifyReadDataCorrect(index, length, bytes)) {
                std::ostringstream oss;
                oss << "Bad data in read buffer at line " << __LINE__;
                BOOST_FAIL(oss.str());
            }
        } catch (std::exception e) {
            LogDebug(e.what());
            std::ostringstream oss;
            oss << e.what();
            BOOST_FAIL("Caught exception: " + oss.str());
        }
        LogDebug("Finished reading");
    }

void test_input_provider_read_getSize(IInputProvider& inputProvider) {
        try {
            size_t fileSize = inputProvider.getSize();

            if (fileSize != buffer_size) {
                std::ostringstream oss;
                oss << "Bad file size returned.  Expected=" << buffer_size << " actual=" << fileSize;
                BOOST_FAIL(oss.str());
            }
        } catch (std::exception e) {
            LogDebug(e.what());
            std::ostringstream oss;
            oss << e.what();
            BOOST_FAIL("Caught exception: " + oss.str());
        }
        LogDebug("Finished reading");
    }

    void test_input_provider_read_buffer_too_small(IInputProvider& inputProvider) {

        std::vector<std::byte> buffer(10);
        WriteableBytes bytes = WriteableBytes{buffer};

        size_t index = 5;
        size_t length = 500;

        // Verify that a too small buffer throws an error
        BOOST_CHECK_THROW(inputProvider.readBytes(index, length, bytes), Exception);

    }

    void test_input_provider_get_size(IInputProvider& inputProvider) {
        size_t testSize = inputProvider.getSize();
        size_t rightAnswer = buffer_size;
        std::ostringstream resultOss;
        resultOss << "testSize=" << testSize << " rightAnswer=" << rightAnswer;
        LogDebug(resultOss.str());
        BOOST_TEST(testSize == rightAnswer);
    }

    void test_input_provider_common(IInputProvider& inputProvider)
    {
        test_input_provider_read(inputProvider);
        test_input_provider_read_partial_mid(inputProvider);
        test_input_provider_read_partial_begin(inputProvider);
        test_input_provider_read_partial_end(inputProvider);
        test_input_provider_read_partial_multiple(inputProvider);
        test_input_provider_get_size(inputProvider);
    }

    BOOST_AUTO_TEST_CASE(test_file_input_provider) {
        Logger::getInstance().enableConsoleLogging();
        Logger::getInstance().setLogLevel(virtru::LogLevel::Trace);

        std::string testFile = "file_io_provider_sample.txt";
        std::string nonexistentTestFile = "nonexistent_file_io_provider_sample.txt";

        remove(testFile.c_str());

        try {
            std::vector<std::byte> buffer(buffer_size);
            WriteableBytes bytes = WriteableBytes{buffer};

            std::byte value;
            for (unsigned long i = 0; i < buffer_size; i++) {
                value = static_cast<std::byte>(i & 0xFF);
                buffer[i] = value;
            }

            virtru::FileOutputProvider fop(testFile);
            fop.writeBytes(bytes);
        } catch (std::exception e) {
            LogDebug(e.what());
            std::ostringstream oss;
            oss << e.what();
            BOOST_FAIL("Caught exception: " + oss.str());
        }
        LogDebug("Finished writing");

        virtru::FileInputProvider fip(testFile);

        test_input_provider_common(fip);

        // Verify that a nonexistent filename throws an error
        BOOST_CHECK_THROW(virtru::FileInputProvider fip2(nonexistentTestFile), Exception);
    }

    BOOST_AUTO_TEST_CASE(test_s3_input_provider) {
        Logger::getInstance().enableConsoleLogging();
        Logger::getInstance().setLogLevel(virtru::LogLevel::Trace);

        // Test sha256 output (correct answer and correct capitalization)
        std::string nullString;
        std::string testSha256 = crypto::hexHashSha256(toBytes(nullString));
        std::string goodSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        BOOST_TEST(testSha256 == goodSha256);

        // Test signing
        std::string testStringToSign="AWS4-HMAC-SHA256\n""20130524T000000Z\n""20130524/us-east-1/s3/aws4_request\n""9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d";
        std::string testSignature =  S3Utilities::generateAwsSignature("AWS4wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "20130524", "us-east-1", "s3", "aws4_request", testStringToSign);
        std::string goodSignature = "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd";
        BOOST_TEST(testSignature == goodSignature);

        std::string S3Url = "https://patman2.s3.us-west-2.amazonaws.com/s3_io_provider_sample.txt";
        // NOTE: these creds have limited access to read/write from our specific bucket
        // NOTE: valid credentials are NOT required for mock network, only for real I/O to S3
        char * akid = getenv("AWS_ACCESS_KEY_ID");                      // Get key ID from environment
        std::string awsAccessKeyId = akid ? akid : "xxxxxxxxx";         //DO NOT PUT ACTUAL ID IN SOURCE CONTROL
        char * asak = getenv("AWS_SECRET_ACCESS_KEY");                  // Get secret key from environment
        std::string awsSecretAccessKey = asak ? asak : "xxxxxxx";       //DO NOT PUT ACTUAL SECRET IN SOURCE CONTROL
        std::string awsRegionName = "us-west-2";

        virtru::S3InputProvider s3ip(S3Url, awsAccessKeyId, awsSecretAccessKey, awsRegionName);

        // Set up mock network - comment out setHttpServiceProvider call to do real I/O to S3
        std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>();
        s3ip.setHttpServiceProvider(mockNetwork);

        test_input_provider_common(s3ip);


    }

BOOST_AUTO_TEST_SUITE_END()
