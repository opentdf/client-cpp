//
//  TDF SDK
//
//  Created by Pat Mancuso on 2022/07/06.
//  Copyright 2022 Virtru Corporation
//

#define BOOST_TEST_MODULE test_big_data

#include "tdf_client.h"
#include "tdf.h"
#include "nanotdf/ecc_mode.h"
#include "nanotdf_client.h"
#include "crypto/ec_key_pair.h"
#include "network/http_client_service.h"
#include "tdf_exception.h"
#include "crypto/rsa_key_pair.h"
#include "oidc_credentials.h"
#include "test_utils.h"
#include "tdf_exception.h"
#include "file_io_provider.h"
#include "tdf_archive_reader.h"

#include <boost/test/included/unit_test.hpp>
#include <boost/endian/arithmetic.hpp>
#include <boost/filesystem.hpp>
#include <iostream>
#include <istream>
#include <fstream>

#ifdef _WINDOWS
#include <direct.h>
#define GetCurrentDir _getcwd
#else
#include <unistd.h>
#define GetCurrentDir getcwd
#endif

// Credentials below assume a local quickstart OIDC environment
#define LOCAL_QUICKSTART_SETUP 0

constexpr auto user = "user1";
constexpr auto user2 = "user2";
constexpr auto easUrl = "http://localhost:8000/";
constexpr auto OIDC_ENDPOINT = "http://localhost:65432/";
constexpr auto KAS_URL = "http://localhost:65432/api/kas";
constexpr auto CLIENT_ID = "tdf-client";
constexpr auto CLIENT_SECRET = "123-456";
constexpr auto ORGANIZATION_NAME = "tdf";


using namespace virtru::network;
using namespace virtru::crypto;
using namespace virtru::nanotdf;
using namespace virtru;

BOOST_AUTO_TEST_SUITE(test_big_data_suite)

#if LOCAL_QUICKSTART_SETUP

BOOST_AUTO_TEST_CASE(test_big_file_local) {

    std::string inPathEncrypt = "big_input_file.txt";
    std::string outPathEncrypt = "big_tdf.tdf";
    std::string inPathDecrypt = outPathEncrypt;
    std::string outPathDecrypt = "big_tdf_decrypted.txt";


#define BIG_WRITE 1
#if BIG_WRITE
    // Create a big input file and then create a TDF from it
    size_t buffer_size = 1024*1024;
    int buffer_count = 1 * 1024;

        remove(inPathEncrypt.c_str());
        remove(outPathEncrypt.c_str());
        remove(outPathDecrypt.c_str());

        try {
            std::vector<std::byte> buffer(buffer_size);
            WriteableBytes bytes = WriteableBytes{buffer};

            // Create buffer of data
            std::byte value;
            for (unsigned long i = 0; i < buffer_size; i++) {
                value = static_cast<std::byte>(i & 0xFF);
                buffer[i] = value;
            }

            // Create input data file of the requested number of buffers size
            std::fstream out(inPathEncrypt, std::ios_base::app | std::ios_base::binary);
            for (int i = 0; i<buffer_count; i++) {
		    out.write(reinterpret_cast<char*>(bytes.data()), bytes.size());
            }
            out.close();

        } catch (std::exception e) {
            LogDebug(e.what());
            std::ostringstream oss;
            oss << e.what();
            BOOST_FAIL("Caught exception: " + oss.str());
        }
        LogDebug("Finished writing");
#endif

        try {

            OIDCCredentials clientCreds;
            clientCreds.setClientCredentialsClientSecret(CLIENT_ID, CLIENT_SECRET,
                                                         ORGANIZATION_NAME, OIDC_ENDPOINT);
            auto oidcClientTDF = std::make_unique<TDFClient>(clientCreds, KAS_URL);

#define BIG_FILE 1

#if BIG_FILE
            // Read from TDF file created in BIG_WRITE step above
            auto attributes = oidcClientTDF->getSubjectAttributes();
            std::cout << "The subject attributes:" << std::endl;
            for(const auto& attribute: attributes) {
                std::cout << attribute << std::endl;
            }

            std::string currentDir = TestUtils::getCurrentWorkingDir();
            const std::string metaData = R"({"displayName" : "opentdf c++ sdk"})";

            oidcClientTDF->setEncryptedMetadata(metaData);

            TDFStorageType encryptFileType;
            encryptFileType.setTDFStorageFileType(inPathEncrypt);
            oidcClientTDF->encryptFileV2(encryptFileType, outPathEncrypt);

            TDFStorageType decryptFileType;
            decryptFileType.setTDFStorageFileType(outPathEncrypt);
            oidcClientTDF->decryptDataPartial(decryptFileType, 0, 100);
#else
        // Read from pre-existing S3 TDF object - must do BIG_WRITE to create TDF, and then upload to S3 before running this
        Logger::getInstance().enableConsoleLogging();
        Logger::getInstance().setLogLevel(virtru::LogLevel::Trace);

        std::string S3Url = "https://patman2.s3.us-west-2.amazonaws.com/big_tdf_1g.tdf";
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

        TDFStorageType decryptS3Type;
        decryptS3Type.setTDFStorageS3Type(S3Url, awsAccessKeyId, awsSecretAccessKey, awsRegionName);
        oidcClientTDF->decryptDataPartial(decryptS3Type, 0, 100);
#endif

        }
        catch (const Exception &exception) {
            BOOST_FAIL(exception.what());
        } catch (const std::exception &exception) {
            BOOST_FAIL(exception.what());
            std::cout << exception.what() << std::endl;
        } catch (...) {
            BOOST_FAIL("Unknown exception...");
            std::cout << "Unknown..." << std::endl;
        }
}
#else
    BOOST_AUTO_TEST_CASE(test_big_file_local_disabled) {
        std::cout << "NO TESTS RUN - REQUIRES LOCAL QUICKSTART BACKEND" << std::endl;
    }
#endif

BOOST_AUTO_TEST_SUITE_END()

