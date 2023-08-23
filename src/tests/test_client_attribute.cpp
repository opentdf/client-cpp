/*
* Copyright 2019 Virtru Corporation
*
* SPDX - License Identifier: BSD-3-Clause-Clear
*
*/
#define BOOST_TEST_MODULE test_client_attribute_suite

#include "tdfbuilder.h"
#include "tdf_client.h"
#include "nanotdf_client.h"
#include "nanotdf_builder.h"
#include "tdf.h"
#include "network/http_client_service.h"
#include "tdf_exception.h"
#include "crypto/rsa_key_pair.h"
#include "entity_object.h"
#include "sdk_constants.h"
#include "crypto/bytes.h"

#include "nlohmann/json.hpp"
#include <jwt-cpp/jwt.h>
#include <boost/test/included/unit_test.hpp>
#include <boost/filesystem.hpp>
#include <stdio.h>
#include <iostream>

#ifdef _WINDOWS
#include <direct.h>
#define GetCurrentDir _getcwd
#else
#include <unistd.h>
#define GetCurrentDir getcwd
#endif

constexpr auto user = "Alice_1234";//"tdf-user@virtrucanary.com";
constexpr auto easUrl =  "https://eas.eternos.xyz/";//"https://accounts-develop01.develop.virtru.com/api";


using namespace virtru::network;
using namespace virtru::crypto;
using namespace virtru;


///returns current working directory
std::string getCurrentWorkingDir() {
    char buff[FILENAME_MAX];
    GetCurrentDir( buff, FILENAME_MAX );
    std::string current_working_dir(buff);
    return current_working_dir;
}


BOOST_AUTO_TEST_SUITE(test_client_attribute_suite)

    using namespace virtru;

    BOOST_AUTO_TEST_CASE(test_client_basic_client) {

        try{
            //auto builder = createTDFBuilder(LogLevel::Warn,KeyAccessType::Wrapped,Protocol::Html);
            TDFClient client(easUrl, user);

            NanoTDFClient nanoTDFClient(easUrl, user);

            BOOST_TEST_MESSAGE("TDFClient and NanoTDFClient basic creation test passed.");
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


    BOOST_AUTO_TEST_CASE(test_nano_builder_ecdsa) {
        try{
            auto builder = NanoTDFBuilder(user);
            // default should be gmac, so ecdsa should be false
            BOOST_CHECK(builder.getECDSABinding() == false);

            // explicitly enable it, verify 
            builder.enableECDSABinding();
            BOOST_CHECK(builder.getECDSABinding() == true);

            // disable it again, verify 
            builder.disableECDSABinding();
            BOOST_CHECK(builder.getECDSABinding() == false);
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
#if 0
    BOOST_AUTO_TEST_CASE(test_basic_client_get_ent_attr) {

        try{
            TDFClient client{easUrl, user};
            NanoTDFClient nanoTDFClient{easUrl, user};

            //should just be default attribute
            std::vector<std::string> correctEntityAttributes = {"https://kas.eternos.xyz/attr/default/value/default"};

            auto entityAttributes = client.getEntityAttributes();
            BOOST_TEST(entityAttributes == correctEntityAttributes);
            BOOST_CHECK(entityAttributes.size() == 1);

            entityAttributes = nanoTDFClient.getEntityAttributes();
            BOOST_TEST(entityAttributes == correctEntityAttributes);
            BOOST_CHECK(entityAttributes.size() == 1);

            BOOST_TEST_MESSAGE("TDFClient and NanoTDFClient basic getEntityAttributes test passed.");
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
#endif


    BOOST_AUTO_TEST_CASE(test_client_add_data_attr) {

        try{
            TDFClient client{easUrl, user};
            NanoTDFClient nanoTDFClient{easUrl, user};

            std::vector<std::string> attributes = {"https://kas.eternos.xyz/attr/testclassification", "https://kas.eternos.xyz/attr/testotherclassification"};
            for (const auto &attrUri : attributes) {
                client.addDataAttribute(attrUri, "");
                nanoTDFClient.addDataAttribute(attrUri, "");
            }

            //check if stored
            auto dataAttributes = client.getDataAttributes();
            BOOST_TEST(dataAttributes == attributes);

            dataAttributes = nanoTDFClient.getDataAttributes();
            BOOST_TEST(dataAttributes == attributes);

            BOOST_TEST_MESSAGE("TDFClient basic addDataAttribute test passed.");
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

    BOOST_AUTO_TEST_CASE(test_client_add_data_attr_with_different_kas) {

        try{
            TDFClient client{easUrl, user};
            NanoTDFClient nanoTDFClient{easUrl, user};
            std::string anotherUrl = "https://kas.virtrucoin.com";

            std::vector<std::string> attributes = {"https://kas.eternos.xyz/attr/testclassification", "https://kas.eternos.xyz/attr/testotherclassification"};
            for (const auto &attrUri : attributes) {
                client.addDataAttribute(attrUri, anotherUrl);
                nanoTDFClient.addDataAttribute(attrUri, anotherUrl);
            }

            //check if stored
            auto dataAttributes = client.getDataAttributes();
            BOOST_TEST(dataAttributes == attributes);

            dataAttributes = nanoTDFClient.getDataAttributes();
            BOOST_TEST(dataAttributes == attributes);

            BOOST_TEST_MESSAGE("TDFClient addDataAttribute with different URL test passed.");
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



BOOST_AUTO_TEST_SUITE_END()
