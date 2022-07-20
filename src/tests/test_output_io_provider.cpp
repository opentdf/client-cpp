/*
* Copyright 2022 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
* Created by Patrick Mancuso on 5/3/22.
*/

#define BOOST_TEST_MODULE test_output_io_provider

#include <iostream>
#include <iomanip>

#include "tdf_exception.h"
#include "logger.h"
#include "stdlib.h"
#include "stdio.h"

#include "boost/test/included/unit_test.hpp"

#include "file_io_provider.h"
#include "s3_io_provider.h"

BOOST_AUTO_TEST_SUITE(test_output_provider_suite)

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
        callback(200, "");
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


    static void test_output_provider_write(IOutputProvider& outputProvider, IInputProvider& inputProvider) {

     Logger::getInstance().enableConsoleLogging();
     Logger::getInstance().setLogLevel(virtru::LogLevel::Trace);

     try {
         std::vector<std::byte> buffer(buffer_size);
         WriteableBytes bytes = WriteableBytes{buffer};

         std::byte value;
         for (unsigned long i = 0; i < buffer_size; i++) {
             value = static_cast<std::byte>(i & 0xFF);
             buffer[i] = value;
         }

         outputProvider.writeBytes(bytes);

     } catch (std::exception e) {
         LogDebug(e.what());
         std::ostringstream oss;
         oss << e.what();
         BOOST_FAIL("Caught exception: " + oss.str());
     }
     LogDebug("Finished writing");
     outputProvider.flush();

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

    void test_output_provider_common(IOutputProvider& outputProvider, IInputProvider& inputProvider)
    {
        test_output_provider_write(outputProvider, inputProvider);
    }

    BOOST_AUTO_TEST_CASE(test_file_output_provider) {
        Logger::getInstance().enableConsoleLogging();
        Logger::getInstance().setLogLevel(virtru::LogLevel::Trace);

        std::string testFile = "file_io_provider_sample.txt";

        remove(testFile.c_str());

        virtru::FileOutputProvider fop(testFile);
        virtru::FileInputProvider fip(testFile);
        test_output_provider_common(fop, fip);

    }

    BOOST_AUTO_TEST_CASE(test_s3_output_provider) {
        Logger::getInstance().enableConsoleLogging();
        Logger::getInstance().setLogLevel(virtru::LogLevel::Trace);

        std::string S3Url = "https://patman2.s3.us-west-2.amazonaws.com/s3_io_provider_output_test.txt";
        // NOTE: these creds have limited access to read/write from our specific bucket
        // NOTE: valid credentials are NOT required for mock network, only for real I/O to S3
        // If credentials are set in environment, they will be used to perform REAL operations to S3, otherwise mock
        bool bUseRealS3 = false;

        char * akid = getenv("AWS_ACCESS_KEY_ID");                      // Get key ID from environment
        std::string awsAccessKeyId;                                     //DO NOT PUT ACTUAL ID IN SOURCE CONTROL

        char * asak = getenv("AWS_SECRET_ACCESS_KEY");                  // Get secret key from environment
        std::string awsSecretAccessKey;                                 //DO NOT PUT ACTUAL SECRET IN SOURCE CONTROL

        if (akid && asak) {
            bUseRealS3 = true;
            awsAccessKeyId = akid;                                      // Use values from environment if set
            awsSecretAccessKey = asak;
        } else {                                                        // Use dummy values for mock
            awsAccessKeyId = "xxxxx";                                   // DO NOT PUT ACTUAL ID IN SOURCE CONTROL
            awsSecretAccessKey = "xxxxx";                               // DO NOT PUT ACTUAL SECRET IN SOURCE CONTROL
        }
        std::string awsRegionName = "us-west-2";

        virtru::S3InputProvider s3ip(S3Url, awsAccessKeyId, awsSecretAccessKey, awsRegionName);
        virtru::S3OutputProvider s3op(S3Url, awsAccessKeyId, awsSecretAccessKey, awsRegionName);

        // Create mock network
        std::shared_ptr<MockNetwork> mockNetwork = std::make_shared<MockNetwork>();

        if (!bUseRealS3) {
            // Enable mock network if not using real S3
            s3ip.setHttpServiceProvider(mockNetwork);
            s3op.setHttpServiceProvider(mockNetwork);
        }

        test_output_provider_common(s3op, s3ip);

    }

BOOST_AUTO_TEST_SUITE_END()
