//
//  TDF SDK
//
//  Created by Sujan Reddy on 2019/03/11.
//  Copyright 2019 Virtru Corporation
//

#define BOOST_TEST_MODULE test_http_client_service

#include "http_client_service.h"
#include "tdf_exception.h"
#include "utils.h"
#include "version.h"

#include <string>
#include <iostream>

#include "nlohmann/json.hpp"
#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(test_http_client_service_suite)

    using namespace virtru::network;

    BOOST_AUTO_TEST_CASE(test_http_client_service_get)
    {
        constexpr auto kasUrl = "https://api-develop01.develop.virtru.com/kas";
        constexpr auto AcceptHeaderKey = "Accept";
        constexpr auto AcceptHeaderValue = "application/json";
        constexpr auto UserAgentHeaderKey = "User-Agent";
        constexpr auto UserAgentValuePostFix = "Virtru TDF C++ SDK v0.1";

        //"Content-Type": "application/json"


        auto service = Service::Create(kasUrl);
        service->AddHeader(AcceptHeaderKey, AcceptHeaderValue);

        // Set user agent (ex: <Mac OS/Linux>:Virtru TDF C++ SDK v0.1)
        std::ostringstream sdkUserAgent {BOOST_PLATFORM};
        sdkUserAgent << ":" << UserAgentValuePostFix;
        service->AddHeader(UserAgentHeaderKey, sdkUserAgent.str());

        IOContext ioContext;
        service->ExecuteGet(ioContext, [](ErrorCode errorCode, HttpResponse&& response) {
            if (errorCode) { // something wrong.

                std::ostringstream os {"Error code: "};
                os << errorCode.value() << " " << errorCode.message();
                BOOST_FAIL(os.str());

                std::cerr << os.str() << std::endl;
                return;
            }

            BOOST_TEST_MESSAGE(response);

            std::string body = response.body().data();
            BOOST_REQUIRE(body.size() > 0);
            return;
        });

        // Run the context - It's blocking call until i/o operation is done.
        ioContext.run();
    }

    BOOST_AUTO_TEST_CASE(test_http_client_service_get_enity_object)
    {

        constexpr auto getEntityUrl = "https://accounts-develop01.develop.virtru.com/api/entityobject";
        //constexpr auto apiId = "2aadbfbd-b68e-4648-ae29-40b4df27ea50@tokens.virtru.com";
        //constexpr auto apiSecret = "f1itK5XJ+M3Gbjzna8yyUXkhKjlqRvzxx2S0mnh6N8Y=";

        constexpr auto AcceptHeaderKey = "Accept";
        constexpr auto AcceptHeaderValue = "application/json";
        constexpr auto UserAgentHeaderKey = "User-Agent";
        constexpr auto UserAgentValuePostFix = "Virtru TDF C++ SDK v0.1";

        // Set user agent (ex: <Mac OS/Linux>:Virtru TDF C++ SDK v0.1)
        std::ostringstream sdkUserAgent;
        sdkUserAgent << BOOST_PLATFORM << ":" << UserAgentValuePostFix;

        auto service = Service::Create(getEntityUrl);
        service->AddHeader(AcceptHeaderKey, AcceptHeaderValue);
        service->AddHeader(UserAgentHeaderKey, sdkUserAgent.str());

        constexpr auto publicKey = "-----BEGIN PUBLIC KEY-----\n"
                                   "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuO0nxhGCyuEbHOqNXjWI\n"
                                   "2dfuNC9jz6J9ZKb3dvosZLtiro32+jgeeudcO0/l1P+RzGkORUGubrkN/oUWtC9l\n"
                                   "DJgq3T05pQJUcg/+sbyL1GvUnU0iJfVk9zz5w3cDBE/I99rCGsIfG2m+unKKJn22\n"
                                   "wd/ZOqQDOwZN6oDkB7ZWQJe0QBQub0lJjThogrPViXIJqRgToH+tsjUX+htkp8QA\n"
                                   "vvkw09Xc1HZ6khZVdfYf7Bm0YI0OVCMbJ77BVsMG0cCsD/8h3/26F7oq9uiaeTnx\n"
                                   "sZBszfBXJGpUm40naaQJ/4CIq20QTadrXLMp1CRMnR5TceLvv/KpGlQGXb4V4zRf\n"
                                   "qQIDAQAB\n"
                                   "-----END PUBLIC KEY-----";

        nlohmann::json publicKeyBody;
        publicKeyBody["publicKey"] = publicKey;

        IOContext ioContext;
        service->ExecutePost(to_string(publicKeyBody), ioContext, [](ErrorCode errorCode, HttpResponse&& response) {
            if (errorCode) { // something wrong.

                std::ostringstream os {"Error code: "};
                os << errorCode.value() << " " << errorCode.message();
                //BOOST_FAIL(os.str());

                std::cerr << os.str() << std::endl;
                auto body = response.body().data();
                std::cerr << body << std::endl;
                return;
            }

            BOOST_TEST_MESSAGE(response);

            auto body = response.body().data();
            std::cerr << body << std::endl;
            //BOOST_TEST(body == "\"It's alive!!! It's alive!!!\"\n");
            return;
        });

        // Run the context - It's blocking call until i/o operation is done.
        ioContext.run();
    }

    BOOST_AUTO_TEST_CASE(test_http_header_version_value)
    {
        std::string utilUserAgent = virtru::Utils::getUserAgentValuePostFix();

        BOOST_CHECK_EQUAL(utilUserAgent, "Openstack C++ SDK v" + std::to_string(opentdf_VERSION_MAJOR) + "." + std::to_string(opentdf_VERSION_MINOR));

        std::string utilClientValue = virtru::Utils::getClientValue();

        BOOST_CHECK_EQUAL(utilClientValue, std::string("openstack-cpp-sdk:") + opentdf_VERSION);
    }

BOOST_AUTO_TEST_SUITE_END()
