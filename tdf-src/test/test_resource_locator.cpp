//
//  TDF SDK
//
//  Created by Sujan Reddy on 2020/06/03.
//  Copyright 2020 Virtru Corporation
//

#define BOOST_TEST_MODULE test_resource_locator_suite

#include <iostream>
#include <fstream>
#include <memory>

#include "tdf_exception.h"
#include "nanotdf/resource_locator.h"
#include "gcm_encryption.h"
#include "gcm_decryption.h"

#include <boost/test/included/unit_test.hpp>

using namespace virtru;
using namespace virtru::nanotdf;


void test_resource_locator(const std::string& url) {

    std::uint16_t resourceLocatorSize = 0;

    { // Write to a file
        std::vector<gsl::byte> contents;

        ResourceLocator resourceLocator{url};
        resourceLocatorSize = resourceLocator.getTotalSize();
        contents.resize(resourceLocatorSize);

        auto toalBytesWriten = resourceLocator.writeIntoBuffer(toWriteableBytes(contents));
        BOOST_TEST(resourceLocatorSize == toalBytesWriten);

        std::ofstream outfile("test.bin", std::ios::out | std::ios::binary);
        outfile.write(reinterpret_cast<const char *>(contents.data()), contents.size());
    }

    { // Read from a file.
        /// Read the resource locator content from the file.
        std::vector<gsl::byte> contents;
        std::ifstream ifs("test.bin", std::ios::binary|std::ios::ate);
        if (!ifs) {
            ThrowException("Failed to open file for reading.");
        }

        std::ifstream::pos_type fileSize = ifs.tellg();
        contents.resize(fileSize);
        ifs.seekg(0, std::ios::beg);
        ifs.read((char*) contents.data(), contents.size());

        ResourceLocator resourceLocator{toBytes(contents)};

        BOOST_TEST(url == resourceLocator.getResourceUrl());
        BOOST_TEST(contents.size() == resourceLocatorSize);\
    }
}

BOOST_AUTO_TEST_SUITE(test_resouce_locator)

    BOOST_AUTO_TEST_CASE(test_nano_tdf_test_resource_loactor) {

        static_assert(sizeof(ResourceLocator::Protocol::HTTPS) == 1, "The resource protocol size should be 1 byte.");

        test_resource_locator("https://heelo.com");
        test_resource_locator("http://localhost:4000/kas");
        test_resource_locator("https://local.virtru.com/kas");

        try {
            test_resource_locator("gopher://local.virtru.com/kas");
            BOOST_FAIL("We should not get here" );
        } catch ( const Exception& exception) {
            BOOST_TEST_MESSAGE("Expect exception");
            std :: cout << exception.what() << std::endl;
        } catch ( ... ) {
            BOOST_FAIL("Exception should be thrown" );
            std :: cout << "...\n";
        }

        std::string localKasUrl("https://local.virtru.com/kas");
        ResourceLocator resourceLocator{localKasUrl};

        BOOST_TEST(localKasUrl == resourceLocator.getResourceUrl());
        BOOST_TEST("http://local.virtru.com/kas" != resourceLocator.getResourceUrl());
    }

BOOST_AUTO_TEST_SUITE_END()